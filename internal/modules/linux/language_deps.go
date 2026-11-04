package linux

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

const maxLangArtifacts = 80
const maxNestedJARs = 40
const maxNodePackages = 400
const maxPyDists = 400

// LanguageDeps discovers Java/Python/Node/Go dependency evidence from running
// processes and their application roots. Does not crawl the full filesystem.
type LanguageDeps struct{}

func (m *LanguageDeps) ID() string          { return "language_deps" }
func (m *LanguageDeps) Version() string     { return "1.1.3" }
func (m *LanguageDeps) Platforms() []string { return []string{"linux"} }

func (m *LanguageDeps) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	partial := false

	procs := listProcessSeeds()
	seen := map[string]bool{}
	artifacts := 0

	// Environment-aware Python inventory (process-led + bounded known locations).
	pyRecs, pyErr, _ := collectPythonInventoryFromSeeds(ctx, procs, defaultPythonScanLimits())
	if pyErr != "" {
		res.Errors = append(res.Errors, common.Err(m.ID(), "partial", pyErr))
		partial = true
	}
	for _, rec := range pyRecs {
		id := asString(rec["entity_id"])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
		artifacts++
		if artifacts >= maxLangArtifacts*20 {
			// Python inventory is denser than other language artifacts; allow a higher soft cap.
			res.Errors = append(res.Errors, common.Err(m.ID(), "record_limit", "language artifact soft cap reached after python inventory"))
			partial = true
			break
		}
	}

	for _, p := range procs {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "language_deps cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}
		if artifacts >= maxLangArtifacts*20 {
			res.Errors = append(res.Errors, common.Err(m.ID(), "record_limit", "language artifact cap reached"))
			partial = true
			break
		}
		exe := p.exe
		base := strings.ToLower(filepath.Base(exe))
		cmd := strings.ToLower(p.cmdline)
		argv0 := base
		if fields := strings.Fields(p.cmdline); len(fields) > 0 {
			argv0 = strings.ToLower(filepath.Base(fields[0]))
		}
		// Symlinked interpreters (e.g. python -> busybox) must be classified by argv0.
		detectBase := base
		if isGenericBusybox(base) || base == "dash" || base == "sh" {
			detectBase = argv0
		}

		switch {
		case isPythonRuntime(detectBase, cmd) || isPythonRuntime(argv0, cmd):
			// Python handled in collectPythonInventoryFromSeeds above.
			continue
		case isNodeRuntime(detectBase, cmd) || isNodeRuntime(argv0, cmd):
			recs, errMsg := collectNodeEvidence(p)
			if errMsg != "" {
				res.Errors = append(res.Errors, common.Err(m.ID(), "partial", errMsg))
				partial = true
			}
			for _, rec := range recs {
				id := asString(rec["entity_id"])
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
				artifacts++
			}
		case isJavaRuntime(detectBase, cmd) || isJavaRuntime(argv0, cmd):
			recs, errMsg := collectJavaEvidence(p)
			if errMsg != "" {
				res.Errors = append(res.Errors, common.Err(m.ID(), "partial", errMsg))
				partial = true
			}
			for _, rec := range recs {
				id := asString(rec["entity_id"])
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
				artifacts++
			}
		default:
			// Go: only when buildinfo is present; never invent versions from filenames.
			if rec, ok := collectGoBuildInfo(exe, p.pid); ok {
				id := asString(rec["entity_id"])
				if id != "" && !seen[id] {
					seen[id] = true
					res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
					artifacts++
				}
			}
		}
	}

	status := "success"
	if partial {
		status = "partial"
	}
	if len(res.Evidence) == 0 {
		status = "unavailable"
		res.Errors = append(res.Errors, common.Err(m.ID(), "not_supported", "no language runtime evidence from process seeds"))
	}
	common.Finish(&res, started, status)
	return res
}

type procSeed struct {
	pid       int
	exe       string
	cmdline   string
	cwd       string
	uid       int
	environ   map[string]string
	mapsHints []string
}

func listProcessSeeds() []procSeed {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []procSeed
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := 0
		for _, c := range e.Name() {
			if c < '0' || c > '9' {
				pid = -1
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid <= 0 {
			continue
		}
		base := "/proc/" + e.Name()
		exe, err := os.Readlink(base + "/exe")
		if err != nil {
			continue
		}
		exe = strings.TrimSuffix(exe, " (deleted)")
		cmdB, _ := os.ReadFile(base + "/cmdline")
		cmd := strings.ReplaceAll(string(cmdB), "\x00", " ")
		cwd, _ := os.Readlink(base + "/cwd")
		out = append(out, procSeed{pid: pid, exe: exe, cmdline: strings.TrimSpace(cmd), cwd: cwd})
	}
	return out
}

func isGenericBusybox(base string) bool {
	return base == "busybox" || base == "busybox.apk" || strings.HasPrefix(base, "busybox")
}

func isPythonRuntime(base, cmd string) bool {
	if strings.HasPrefix(base, "python") {
		return true
	}
	// Avoid matching arbitrary cmdline tokens containing "python" as substring in paths only when exe is python-like.
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	b0 := strings.ToLower(filepath.Base(fields[0]))
	return strings.HasPrefix(b0, "python")
}

func isNodeRuntime(base, cmd string) bool {
	return base == "node" || base == "nodejs" || strings.Contains(cmd, "node ")
}

func isJavaRuntime(base, cmd string) bool {
	return base == "java" || base == "jsvc" || strings.Contains(cmd, "java ") || strings.Contains(cmd, "/java ")
}

func pythonVersionFromPath(exe string) string {
	base := filepath.Base(exe)
	// Only accept explicit major.minor in the binary name (e.g. python3.10).
	if strings.HasPrefix(base, "python") {
		rest := strings.TrimPrefix(base, "python")
		if strings.Count(rest, ".") >= 1 {
			// python3.10 → 3.10
			return rest
		}
	}
	return ""
}

func collectNodeEvidence(p procSeed) ([]map[string]any, string) {
	var out []map[string]any
	appRoot := findNodeAppRoot(p)
	out = append(out, map[string]any{
		"entity_type":            "language_runtime",
		"entity_id":              "lang:node:runtime:" + itoa(p.pid),
		"language":               "nodejs",
		"runtime_path":           p.exe,
		"runtime_version":        nil,
		"runtime_version_status": "unknown_not_executed",
		"process_id":             p.pid,
		"command_line":           RedactSecrets(p.cmdline),
		"application_root":       nullIfEmpty(appRoot),
		"discovery_seed":         "process",
	})
	if appRoot == "" {
		return out, "node_application_root_unknown"
	}
	pkgJSON := filepath.Join(appRoot, "package.json")
	declared := map[string]any{}
	if b, err := os.ReadFile(pkgJSON); err == nil {
		_ = json.Unmarshal(b, &declared)
	}
	lockState := readNodeLockfiles(appRoot)
	installed := readNodeModules(filepath.Join(appRoot, "node_modules"))
	out = append(out, map[string]any{
		"entity_type":              "node_application",
		"entity_id":                "lang:node:app:" + hashShort(appRoot),
		"language":                 "nodejs",
		"application_root":         appRoot,
		"process_id":               p.pid,
		"declared_dependencies":    declared["dependencies"],
		"declared_devDependencies": declared["devDependencies"],
		"lockfile":                 lockState,
		"installed_packages":       installed,
		"installed_count":          len(installed),
		"state_notes":              nodeStateNotes(declared, lockState, installed),
	})
	return out, ""
}

func findNodeAppRoot(p procSeed) string {
	// Prefer cwd if package.json exists; else walk cmdline args for script path.
	if p.cwd != "" {
		if _, err := os.Stat(filepath.Join(p.cwd, "package.json")); err == nil {
			return p.cwd
		}
		if _, err := os.Stat(filepath.Join(p.cwd, "node_modules")); err == nil {
			return p.cwd
		}
	}
	for _, tok := range strings.Fields(p.cmdline) {
		if strings.HasSuffix(tok, ".js") || strings.HasSuffix(tok, ".mjs") || strings.HasSuffix(tok, ".cjs") {
			dir := filepath.Dir(tok)
			if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
				return dir
			}
		}
	}
	return ""
}

func readNodeLockfiles(root string) map[string]any {
	out := map[string]any{}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		path := filepath.Join(root, name)
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			out[name] = map[string]any{
				"present": true,
				"path":    path,
				"size":    st.Size(),
			}
		}
	}
	return out
}

func readNodeModules(dir string) []map[string]any {
	var out []map[string]any
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if name == ".bin" {
			continue
		}
		if strings.HasPrefix(name, "@") && e.IsDir() {
			scopeDir := filepath.Join(dir, name)
			scoped, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, s := range scoped {
				if !s.IsDir() {
					continue
				}
				if rec := readNodePackage(filepath.Join(scopeDir, s.Name()), name+"/"+s.Name()); rec != nil {
					out = append(out, rec)
				}
				if len(out) >= maxNodePackages {
					return out
				}
			}
			continue
		}
		if e.IsDir() {
			if rec := readNodePackage(filepath.Join(dir, name), name); rec != nil {
				out = append(out, rec)
			}
		}
		if len(out) >= maxNodePackages {
			break
		}
	}
	return out
}

func readNodePackage(dir, logicalName string) map[string]any {
	b, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var meta map[string]any
	if json.Unmarshal(b, &meta) != nil {
		return nil
	}
	name := asString(meta["name"])
	if name == "" {
		name = logicalName
	}
	ver := asString(meta["version"])
	return map[string]any{
		"entity_type": "node_package",
		// Stable id: name + path hash (version is a field, not part of the id).
		"entity_id": "lang:node:pkg:" + strings.ToLower(name) + ":" + hashShort(dir),
		"name":      name,
		"version":   nullIfEmpty(ver),
		"path":      dir,
		"state":     "installed",
	}
}

func nodeStateNotes(declared map[string]any, lock map[string]any, installed []map[string]any) []string {
	var notes []string
	if len(lock) == 0 {
		notes = append(notes, "no_lockfile")
	}
	if len(installed) == 0 {
		notes = append(notes, "node_modules_absent_or_empty")
	}
	if declared["dependencies"] != nil && len(installed) == 0 {
		notes = append(notes, "declared_without_installed")
	}
	return notes
}

func collectJavaEvidence(p procSeed) ([]map[string]any, string) {
	var out []map[string]any
	out = append(out, map[string]any{
		"entity_type":            "language_runtime",
		"entity_id":              "lang:java:runtime:" + itoa(p.pid),
		"language":               "java",
		"runtime_path":           p.exe,
		"runtime_version":        nil,
		"runtime_version_status": "unknown_not_executed",
		"process_id":             p.pid,
		"command_line":           RedactSecrets(p.cmdline),
		"discovery_seed":         "process",
	})
	jars := javaClasspathJARs(p)
	var jarRecs []map[string]any
	for i, jar := range jars {
		if i >= 30 {
			break
		}
		rec := inspectJAR(jar)
		if rec != nil {
			jarRecs = append(jarRecs, rec)
		}
	}
	if len(jarRecs) > 0 {
		out = append(out, map[string]any{
			"entity_type": "java_application",
			"entity_id":   "lang:java:app:" + itoa(p.pid),
			"language":    "java",
			"process_id":  p.pid,
			"jars":        jarRecs,
			"jar_count":   len(jarRecs),
		})
	}
	return out, ""
}

func javaClasspathJARs(p procSeed) []string {
	var jars []string
	fields := strings.Fields(p.cmdline)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if f == "-jar" && i+1 < len(fields) {
			jars = append(jars, fields[i+1])
			continue
		}
		if f == "-cp" || f == "-classpath" {
			if i+1 < len(fields) {
				for _, part := range strings.Split(fields[i+1], ":") {
					if strings.HasSuffix(strings.ToLower(part), ".jar") || strings.HasSuffix(strings.ToLower(part), ".war") || strings.HasSuffix(strings.ToLower(part), ".ear") {
						jars = append(jars, part)
					}
				}
			}
		}
		low := strings.ToLower(f)
		if strings.HasSuffix(low, ".jar") || strings.HasSuffix(low, ".war") || strings.HasSuffix(low, ".ear") {
			jars = append(jars, f)
		}
	}
	return uniqueStrings(jars)
}

func inspectJAR(path string) map[string]any {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	sum, err := sha256File(path)
	if err != nil {
		sum = ""
	}
	manifest, pom := readJARMetadata(path)
	rec := map[string]any{
		"entity_type":              "java_archive",
		"entity_id":                "lang:java:jar:" + hashShort(path+sum),
		"path":                     path,
		"sha256":                   nullIfEmpty(sum),
		"size_bytes":               st.Size(),
		"manifest":                 manifest,
		"pom_properties":           pom,
		"implementation_version":   nullIfEmpty(asString(manifest["Implementation-Version"])),
		"bundle_symbolic_name":     nullIfEmpty(asString(manifest["Bundle-SymbolicName"])),
		"filename_version_trusted": false,
	}
	// Nested / Spring Boot fat JAR: list BOOT-INF/lib entries without extracting payloads deeply.
	nested := listNestedJARs(path)
	if len(nested) > 0 {
		rec["nested_jars"] = nested
		rec["nested_jar_count"] = len(nested)
		rec["spring_boot_fat_jar"] = hasPrefixAny(nested, "BOOT-INF/lib/")
	}
	return rec
}

func readJARMetadata(path string) (map[string]string, map[string]string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	// Minimal ZIP central-directory free scan via archive/zip
	return readZipManifestAndPom(path)
}

func listNestedJARs(path string) []string {
	return listZipSuffix(path, ".jar", maxNestedJARs)
}

func collectGoBuildInfo(exe string, pid int) (map[string]any, bool) {
	bi, err := buildinfo.ReadFile(exe)
	if err != nil {
		// Explicit absence: stripped or non-Go binary — do not fabricate.
		return nil, false
	}
	deps := make([]map[string]any, 0, len(bi.Deps))
	for _, d := range bi.Deps {
		if d == nil {
			continue
		}
		deps = append(deps, map[string]any{
			"path":    d.Path,
			"version": d.Version,
			"sum":     d.Sum,
		})
	}
	settings := map[string]string{}
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	mainPath, mainVer := "", ""
	if bi.Main.Path != "" {
		mainPath = bi.Main.Path
		mainVer = bi.Main.Version
	}
	return map[string]any{
		"entity_type":         "go_binary",
		"entity_id":           "lang:go:bin:" + hashShort(exe),
		"language":            "go",
		"path":                exe,
		"process_id":          pid,
		"go_version":          bi.GoVersion,
		"main_module_path":    nullIfEmpty(mainPath),
		"main_module_version": nullIfEmpty(mainVer),
		"dependencies":        deps,
		"dependency_count":    len(deps),
		"build_settings":      settings,
		"vcs_revision":        nullIfEmpty(settings["vcs.revision"]),
		"buildinfo_present":   true,
	}, true
}

func hashShort(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func hasPrefixAny(items []string, prefix string) bool {
	for _, i := range items {
		if strings.HasPrefix(i, prefix) {
			return true
		}
	}
	return false
}
