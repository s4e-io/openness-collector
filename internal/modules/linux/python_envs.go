package linux

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Bounded controls for environment-aware Python inventory.
const (
	maxPythonEnvs         = 40
	maxPythonMetaFiles    = 2000
	maxPythonSearchDepth  = 4
	maxPythonMapsHints    = 64
	maxPythonDistsPerEnv  = 800
	maxPythonSkippedNotes = 200
)

var pep503Re = regexp.MustCompile(`[-_.]+`)

type pythonScanLimits struct {
	maxEnvs      int
	maxMetaFiles int
	maxDepth     int
}

func defaultPythonScanLimits() pythonScanLimits {
	return pythonScanLimits{
		maxEnvs:      maxPythonEnvs,
		maxMetaFiles: maxPythonMetaFiles,
		maxDepth:     maxPythonSearchDepth,
	}
}

type pythonScanState struct {
	limits           pythonScanLimits
	envByRoot        map[string]string         // env root -> envID
	envByInode       map[string]string         // dev:ino -> envID
	envRecords       map[string]map[string]any // envID -> mutable environment entity
	envInterp        map[string]string         // envID -> interpreter entity ID
	distByEnv        map[string][]map[string]any
	distRecords      map[string]map[string]any // dist entity_id -> distribution entity
	distByOSPkg      map[string]string         // pkg:dpkg:... -> dist entity_id (exact OS ownership link)
	osPkgByDist      map[string]string         // dist entity_id -> pkg:dpkg:...
	seenDistID       map[string]bool
	seenInterp       map[string]bool
	interpRecords    map[string]map[string]any
	seenRel          map[string]bool
	metaFiles        int
	skipped          []map[string]any
	coverage         pythonCoverage
	mappedFilesByPID map[int][]string
	dpkgIdx          *dpkgOwnershipIndex
	pendingLoadRels  []map[string]any
}

func (st *pythonScanState) dpkg() *dpkgOwnershipIndex {
	if st.dpkgIdx == nil {
		st.dpkgIdx = newDpkgOwnershipIndex()
	}
	return st.dpkgIdx
}

type pythonCoverage struct {
	Interpreters                 int            `json:"interpreters_discovered"`
	Environments                 int            `json:"environments_discovered"`
	Distributions                int            `json:"distributions_discovered"`
	EnvsConnectedToProcesses     int            `json:"environments_connected_to_running_processes"`
	PackagesCompleteIdentity     int            `json:"packages_with_complete_identity"`
	PackagesUnknownVersion       int            `json:"packages_with_unknown_version"`
	DistributionsInActiveEnvs    int            `json:"distributions_in_active_environments"`
	DistributionsConfirmedLoaded int            `json:"distributions_confirmed_loaded"`
	SkippedPaths                 int            `json:"skipped_paths"`
	SkippedByReason              map[string]int `json:"skipped_by_reason"`
	CollectionErrors             []string       `json:"collection_errors"`
	EnvKinds                     map[string]int `json:"environment_kinds"`
}

func newPythonScanState(lim pythonScanLimits) *pythonScanState {
	return &pythonScanState{
		limits:           lim,
		envByRoot:        map[string]string{},
		envByInode:       map[string]string{},
		envRecords:       map[string]map[string]any{},
		envInterp:        map[string]string{},
		distByEnv:        map[string][]map[string]any{},
		distRecords:      map[string]map[string]any{},
		distByOSPkg:      map[string]string{},
		osPkgByDist:      map[string]string{},
		seenDistID:       map[string]bool{},
		seenInterp:       map[string]bool{},
		interpRecords:    map[string]map[string]any{},
		seenRel:          map[string]bool{},
		mappedFilesByPID: map[int][]string{},
		coverage: pythonCoverage{
			SkippedByReason: map[string]int{},
			EnvKinds:        map[string]int{},
		},
	}
}

func (st *pythonScanState) registerDistOSPackage(distID, osPkgID string) {
	if distID == "" || osPkgID == "" {
		return
	}
	st.osPkgByDist[distID] = osPkgID
	// One OS binary package maps to exactly one inventoried Python distribution.
	st.distByOSPkg[osPkgID] = distID
}

func (st *pythonScanState) skip(path, reason string) {
	reason = normalizePythonSkipReason(reason)
	st.coverage.SkippedPaths++
	st.coverage.SkippedByReason[reason]++
	if len(st.skipped) < maxPythonSkippedNotes {
		st.skipped = append(st.skipped, map[string]any{
			"path":   path,
			"reason": reason,
		})
	}
}

func normalizePythonSkipReason(reason string) string {
	switch reason {
	case "not_found", "permission_denied", "not_directory", "no_metadata", "inode_dedup", "scan_limit", "timeout":
		return reason
	case "path_missing_or_moved", "path_dedup":
		if reason == "path_dedup" {
			return "inode_dedup"
		}
		return "not_found"
	case "not_a_directory":
		return "not_directory"
	case "broken_or_incomplete_metadata", "conda_meta_unreadable":
		return "no_metadata"
	case "max_environments", "max_metadata_files", "python_env_limit", "python_meta_limit", "python_dist_limit":
		return "scan_limit"
	case "site_packages_unreadable":
		return "not_found"
	default:
		return reason
	}
}

func skipReasonFromPathError(err error) string {
	if err == nil {
		return "not_found"
	}
	if os.IsNotExist(err) {
		return "not_found"
	}
	if os.IsPermission(err) {
		return "permission_denied"
	}
	return "not_found"
}

// collectPythonEvidence performs process-led, environment-aware Python inventory.
// Emits separate entities: interpreter, environment, distribution, process refs,
// plus deterministic relationships. Does not execute interpreters or pip.
func collectPythonEvidence(p procSeed) ([]map[string]any, string) {
	return collectPythonEvidenceLimited(p, defaultPythonScanLimits(), nil)
}

func collectPythonEvidenceLimited(p procSeed, lim pythonScanLimits, extraRoots []pythonEnvHint) ([]map[string]any, string) {
	st := newPythonScanState(lim)
	var out []map[string]any
	partialMsg := ""

	p = enrichPythonProc(p)

	// Process entity (lightweight; full process module is authoritative elsewhere).
	procEnt := map[string]any{
		"entity_type":       "process",
		"entity_id":         "process:" + itoa(p.pid),
		"process_id":        p.pid,
		"executable_path":   nullIfEmpty(p.exe),
		"command_line":      RedactSecrets(p.cmdline),
		"working_directory": nullIfEmpty(p.cwd),
		"owner_uid":         p.uid,
		"discovery_source":  "proc",
		"collection_status": "observed",
	}
	out = append(out, procEnt)

	hints := discoverPythonEnvHintsFromProcess(p)
	hints = append(hints, extraRoots...)
	hints = append(hints, boundedPythonKnownLocations(p)...)

	activeEnvIDs := map[string]bool{}

	st.mappedFilesByPID[p.pid] = pythonMappedFiles("/proc/" + itoa(p.pid) + "/maps")
	for _, h := range hints {
		if len(st.envRecords) >= st.limits.maxEnvs && st.envByRoot[filepath.Clean(h.root)] == "" {
			st.skip(h.root, "scan_limit")
			partialMsg = "scan_limit"
			break
		}
		if st.metaFiles >= st.limits.maxMetaFiles {
			st.skip(h.root, "scan_limit")
			partialMsg = "scan_limit"
			break
		}
		ents, rels, envID, errMsg := materializePythonEnvironment(st, h, p)
		if errMsg != "" {
			st.coverage.CollectionErrors = append(st.coverage.CollectionErrors, errMsg)
			if partialMsg == "" {
				partialMsg = errMsg
			}
		}
		out = append(out, ents...)
		out = append(out, rels...)
		if h.activeForPID == p.pid && envID != "" {
			activeEnvIDs[envID] = true
		}
	}
	finalizePythonActiveCoverage(st, activeEnvIDs)
	out = append(out, st.pendingLoadRels...)
	st.coverage.EnvsConnectedToProcesses = len(activeEnvIDs)
	// Attach coverage + skipped as a summary entity for reporting.
	out = append(out, map[string]any{
		"entity_type":       "python_inventory_coverage",
		"entity_id":         "python:coverage:" + itoa(p.pid),
		"process_id":        p.pid,
		"coverage":          st.coverage,
		"skipped_paths":     st.skipped,
		"collection_status": "observed",
	})
	return out, partialMsg
}

// collectPythonInventoryFromSeeds scans multiple processes and inactive known roots once.
// Used by LanguageDeps for host-wide Python inventory with deduplication.
func collectPythonInventoryFromSeeds(ctx context.Context, seeds []procSeed, lim pythonScanLimits) ([]map[string]any, string, pythonCoverage) {
	st := newPythonScanState(lim)
	var out []map[string]any
	partialMsg := ""
	seenProc := map[int]bool{}
	activeEnvIDs := map[string]bool{}

	// Process-led
	for _, raw := range seeds {
		select {
		case <-ctx.Done():
			return out, "timeout", st.coverage
		default:
		}
		if !isPythonProcCandidate(raw) {
			continue
		}
		p := enrichPythonProc(raw)
		if seenProc[p.pid] {
			continue
		}
		seenProc[p.pid] = true

		out = append(out, map[string]any{
			"entity_type":       "process",
			"entity_id":         "process:" + itoa(p.pid),
			"process_id":        p.pid,
			"executable_path":   nullIfEmpty(p.exe),
			"command_line":      RedactSecrets(p.cmdline),
			"working_directory": nullIfEmpty(p.cwd),
			"owner_uid":         p.uid,
			"discovery_source":  "proc",
			"collection_status": "observed",
		})
		st.mappedFilesByPID[p.pid] = pythonMappedFiles("/proc/" + itoa(p.pid) + "/maps")

		for _, h := range append(discoverPythonEnvHintsFromProcess(p), boundedPythonKnownLocations(p)...) {
			if len(st.envRecords) >= st.limits.maxEnvs && st.envByRoot[filepath.Clean(h.root)] == "" {
				st.skip(h.root, "scan_limit")
				partialMsg = "scan_limit"
				break
			}
			if st.metaFiles >= st.limits.maxMetaFiles {
				st.skip(h.root, "scan_limit")
				partialMsg = "scan_limit"
				break
			}
			ents, rels, envID, errMsg := materializePythonEnvironment(st, h, p)
			if errMsg != "" {
				st.coverage.CollectionErrors = append(st.coverage.CollectionErrors, errMsg)
				if partialMsg == "" {
					partialMsg = errMsg
				}
			}
			out = append(out, ents...)
			out = append(out, rels...)
			if h.activeForPID == p.pid && envID != "" {
				activeEnvIDs[envID] = true
			}
		}
	}

	finalizePythonActiveCoverage(st, activeEnvIDs)
	out = append(out, st.pendingLoadRels...)
	st.coverage.EnvsConnectedToProcesses = len(activeEnvIDs)
	out = append(out, map[string]any{
		"entity_type":       "python_inventory_coverage",
		"entity_id":         "python:coverage:host",
		"coverage":          st.coverage,
		"skipped_paths":     st.skipped,
		"collection_status": "observed",
	})
	return out, partialMsg, st.coverage
}

type pythonEnvHint struct {
	root         string
	kind         string // system|venv|virtualenv|user_site|pipx|poetry|conda|unknown
	scope        string // host|container
	discovery    string // process_environ|process_exe|process_cwd|process_maps|known_location|pyvenv_cfg
	activeForPID int    // 0 if inactive
	interpreter  string
	envID        string // filled after materialize
}

func isPythonProcCandidate(p procSeed) bool {
	base := strings.ToLower(filepath.Base(p.exe))
	cmd := strings.ToLower(p.cmdline)
	argv0 := base
	if fields := strings.Fields(p.cmdline); len(fields) > 0 {
		argv0 = strings.ToLower(filepath.Base(fields[0]))
	}
	detect := base
	if isGenericBusybox(base) || base == "dash" || base == "sh" {
		detect = argv0
	}
	if isPythonRuntime(detect, cmd) || isPythonRuntime(argv0, cmd) {
		return true
	}
	// Non-python binary that still runs inside a venv (e.g. gunicorn from venv/bin).
	if strings.Contains(p.exe, "/bin/") {
		root := filepath.Dir(filepath.Dir(p.exe))
		if _, err := os.Stat(filepath.Join(root, "pyvenv.cfg")); err == nil {
			return true
		}
	}
	return false
}

func enrichPythonProc(p procSeed) procSeed {
	base := "/proc/" + itoa(p.pid)
	if p.environ == nil {
		p.environ = readProcEnviron(base + "/environ")
	}
	if p.uid == 0 {
		if st, err := os.Stat(base); err == nil {
			p.uid = fileOwnerUID(st)
		}
	}
	if len(p.mapsHints) == 0 {
		p.mapsHints = pythonHintsFromMaps(base + "/maps")
	}
	// Prefer argv0 when it is the interpreter path.
	if fields := strings.Fields(p.cmdline); len(fields) > 0 {
		b0 := strings.ToLower(filepath.Base(fields[0]))
		if strings.HasPrefix(b0, "python") && strings.Contains(fields[0], "/") {
			p.exe = fields[0]
		}
	}
	p.exe = strings.TrimSuffix(p.exe, " (deleted)")
	return p
}

func readProcEnviron(path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(string(b), "\x00") {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "VIRTUAL_ENV", "CONDA_PREFIX", "PYTHONHOME", "PYTHONPATH", "POETRY_ACTIVE", "HOME", "USER":
			out[k] = v
		}
	}
	return out
}

func pythonHintsFromMaps(mapsPath string) []string {
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		path = strings.TrimSuffix(path, " (deleted)")
		if path == "" || strings.HasPrefix(path, "[") {
			continue
		}
		if !strings.Contains(path, "site-packages") && !strings.Contains(path, "dist-packages") && !strings.Contains(path, "/lib/python") {
			continue
		}
		root := inferEnvRootFromPath(path)
		if root == "" || seen[root] {
			continue
		}
		seen[root] = true
		out = append(out, root)
		if len(out) >= maxPythonMapsHints {
			break
		}
	}
	return out
}

func inferEnvRootFromPath(path string) string {
	// .../lib/pythonX.Y/site-packages/... → env root two or three levels up
	parts := strings.Split(filepath.Clean(path), string(os.PathSeparator))
	for i := 0; i < len(parts); i++ {
		if parts[i] == "site-packages" || parts[i] == "dist-packages" {
			// expect .../lib/pythonX.Y/site-packages
			if i >= 2 && strings.HasPrefix(parts[i-1], "python") && parts[i-2] == "lib" {
				return "/" + filepath.Join(parts[:i-2]...)
			}
			if i >= 1 {
				return "/" + filepath.Join(parts[:i]...)
			}
		}
	}
	if idx := strings.Index(path, "/pyvenv.cfg"); idx > 0 {
		return filepath.Dir(path)
	}
	return ""
}

func discoverPythonEnvHintsFromProcess(p procSeed) []pythonEnvHint {
	var hints []pythonEnvHint
	add := func(root, kind, discovery string, active bool) {
		root = filepath.Clean(root)
		if root == "" || root == "." || root == "/" {
			return
		}
		for _, h := range hints {
			if h.root == root {
				return
			}
		}
		h := pythonEnvHint{
			root:      root,
			kind:      kind,
			scope:     scopeForPath(root),
			discovery: discovery,
		}
		if active {
			h.activeForPID = p.pid
		}
		if p.exe != "" {
			h.interpreter = p.exe
		}
		hints = append(hints, h)
	}

	env := p.environ
	if env == nil {
		env = map[string]string{}
	}
	if v := env["VIRTUAL_ENV"]; v != "" {
		kind := "venv"
		if _, err := os.Stat(filepath.Join(v, "pyvenv.cfg")); err != nil {
			kind = "virtualenv"
		}
		// pipx layout: .../pipx/venvs/<app>
		if strings.Contains(v, "/pipx/venvs/") {
			kind = "pipx"
		}
		if env["POETRY_ACTIVE"] == "1" || strings.Contains(v, "pypoetry") || strings.Contains(v, "/poetry") {
			kind = "poetry"
		}
		add(v, kind, "process_environ:VIRTUAL_ENV", true)
	}
	if v := env["CONDA_PREFIX"]; v != "" {
		add(v, "conda", "process_environ:CONDA_PREFIX", true)
	}
	if v := env["PYTHONHOME"]; v != "" {
		add(v, "system", "process_environ:PYTHONHOME", true)
	}

	// exe in <env>/bin/python*
	if strings.Contains(p.exe, "/bin/") {
		root := filepath.Dir(filepath.Dir(p.exe))
		if _, err := os.Stat(filepath.Join(root, "pyvenv.cfg")); err == nil {
			kind := "venv"
			if strings.Contains(root, "/pipx/venvs/") {
				kind = "pipx"
			}
			if strings.Contains(root, "pypoetry") {
				kind = "poetry"
			}
			add(root, kind, "process_exe", true)
		}
		if _, err := os.Stat(filepath.Join(root, "conda-meta")); err == nil {
			add(root, "conda", "process_exe", true)
		}
	}

	// cwd .venv / venv / poetry
	if p.cwd != "" {
		for _, name := range []string{".venv", "venv"} {
			cand := filepath.Join(p.cwd, name)
			if _, err := os.Stat(filepath.Join(cand, "pyvenv.cfg")); err == nil {
				kind := "venv"
				if _, err := os.Stat(filepath.Join(p.cwd, "poetry.lock")); err == nil {
					kind = "poetry"
				}
				add(cand, kind, "process_cwd", true)
			}
		}
		if _, err := os.Stat(filepath.Join(p.cwd, "poetry.lock")); err == nil {
			// poetry may use cache venv; still mark cwd-associated .venv if present
		}
	}

	for _, root := range p.mapsHints {
		kind := classifyEnvKind(root)
		add(root, kind, "process_maps", true)
	}

	// System interpreter: associate dist-packages near runtime without claiming a venv.
	if isSystemPythonPath(p.exe) {
		for _, root := range systemPythonRootsNear(p.exe) {
			add(root, "system", "process_exe_system", true)
		}
	}
	return hints
}

func boundedPythonKnownLocations(p procSeed) []pythonEnvHint {
	var hints []pythonEnvHint
	add := func(root, kind, discovery string) {
		root = filepath.Clean(root)
		if root == "" {
			return
		}
		st, err := os.Stat(root)
		if err != nil {
			return
		}
		if !st.IsDir() {
			return
		}
		for _, h := range hints {
			if h.root == root {
				return
			}
		}
		hints = append(hints, pythonEnvHint{
			root:      root,
			kind:      kind,
			scope:     scopeForPath(root),
			discovery: discovery,
			// inactive unless also process-linked later
		})
	}

	home := ""
	if p.environ != nil {
		home = p.environ["HOME"]
	}
	if home == "" && p.uid > 0 {
		home = guessHomeForUID(p.uid)
	}
	if home != "" {
		// user-site
		localLib := filepath.Join(home, ".local", "lib")
		_ = filepath.WalkDir(localLib, func(path string, d os.DirEntry, err error) error {
			if err != nil || d == nil {
				return nil
			}
			rel, _ := filepath.Rel(localLib, path)
			if rel != "." && strings.Count(rel, string(os.PathSeparator)) >= maxPythonSearchDepth {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() && (d.Name() == "site-packages" || d.Name() == "dist-packages") {
				// user-site env root is .../.local
				add(filepath.Join(home, ".local"), "user_site", "known_location:user_site")
				return filepath.SkipDir
			}
			return nil
		})
		// pipx
		pipxRoot := filepath.Join(home, ".local", "share", "pipx", "venvs")
		entries, _ := os.ReadDir(pipxRoot)
		for i, e := range entries {
			if i >= 20 {
				break
			}
			if e.IsDir() {
				add(filepath.Join(pipxRoot, e.Name()), "pipx", "known_location:pipx")
			}
		}
		// poetry cache venvs
		for _, poetryRoot := range []string{
			filepath.Join(home, ".cache", "pypoetry", "virtualenvs"),
			filepath.Join(home, "Library", "Caches", "pypoetry", "virtualenvs"),
		} {
			entries, _ := os.ReadDir(poetryRoot)
			for i, e := range entries {
				if i >= 20 {
					break
				}
				if e.IsDir() {
					add(filepath.Join(poetryRoot, e.Name()), "poetry", "known_location:poetry")
				}
			}
		}
		// conda envs
		for _, condaBase := range []string{
			filepath.Join(home, "miniconda3"),
			filepath.Join(home, "anaconda3"),
			filepath.Join(home, "mambaforge"),
			filepath.Join(home, "miniforge3"),
		} {
			if _, err := os.Stat(filepath.Join(condaBase, "conda-meta")); err == nil {
				add(condaBase, "conda", "known_location:conda_base")
			}
			envDir := filepath.Join(condaBase, "envs")
			entries, _ := os.ReadDir(envDir)
			for i, e := range entries {
				if i >= 20 {
					break
				}
				if e.IsDir() {
					add(filepath.Join(envDir, e.Name()), "conda", "known_location:conda_env")
				}
			}
		}
	}
	return hints
}

func guessHomeForUID(uid int) string {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	want := ":" + itoa(uid) + ":"
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, want) {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) >= 6 {
			return parts[5]
		}
	}
	return ""
}

func classifyEnvKind(root string) string {
	if strings.Contains(root, "/pipx/venvs/") {
		return "pipx"
	}
	if strings.Contains(root, "pypoetry") {
		return "poetry"
	}
	if _, err := os.Stat(filepath.Join(root, "conda-meta")); err == nil {
		return "conda"
	}
	if _, err := os.Stat(filepath.Join(root, "pyvenv.cfg")); err == nil {
		return "venv"
	}
	if strings.Contains(root, "/.local") {
		return "user_site"
	}
	if isSystemPythonRoot(root) {
		return "system"
	}
	return "unknown"
}

func isSystemPythonPath(exe string) bool {
	return strings.HasPrefix(exe, "/usr/bin/python") ||
		strings.HasPrefix(exe, "/usr/local/bin/python") ||
		strings.HasPrefix(exe, "/bin/python")
}

func isSystemPythonRoot(root string) bool {
	return root == "/usr" || root == "/usr/local" || strings.HasPrefix(root, "/usr/lib/python")
}

func systemPythonRootsNear(exe string) []string {
	// Represent system env as /usr (dist-packages under /usr/lib/pythonX.Y)
	var roots []string
	if strings.HasPrefix(exe, "/usr/") {
		roots = append(roots, "/usr")
	}
	if strings.HasPrefix(exe, "/usr/local/") {
		roots = append(roots, "/usr/local")
	}
	return roots
}

func scopeForPath(path string) string {
	// Container filesystems mounted on host (docker overlay, etc.)
	low := strings.ToLower(path)
	if strings.Contains(low, "/var/lib/docker/") ||
		strings.Contains(low, "/var/lib/containerd/") ||
		strings.Contains(low, "/var/lib/containers/") ||
		strings.Contains(low, "/run/containerd/") ||
		strings.HasPrefix(path, "/proc/") && strings.Contains(path, "/root/") {
		return "container"
	}
	return "host"
}

func materializePythonEnvironment(st *pythonScanState, h pythonEnvHint, p procSeed) (ents []map[string]any, rels []map[string]any, envID string, errMsg string) {
	root := filepath.Clean(h.root)
	kind := h.kind
	if kind == "" || kind == "unknown" {
		kind = classifyEnvKind(root)
	}
	envID = "python:env:" + hashShort(root+":"+kind)

	fi, err := os.Stat(root)
	if err != nil {
		st.skip(root, skipReasonFromPathError(err))
		if st.envRecords[envID] == nil {
			envRec := map[string]any{
				"entity_type":        "python_environment",
				"entity_id":          envID,
				"environment_root":   root,
				"kind":               kind,
				"scope":              h.scope,
				"discovery_source":   h.discovery,
				"collection_status":  "unavailable",
				"unavailable_reason": "not_found",
				"process_ids":        []int{},
			}
			st.envRecords[envID] = envRec
			st.envByRoot[root] = envID
			st.coverage.Environments++
			st.coverage.EnvKinds[kind]++
			ents = append(ents, envRec)
		}
		rels = append(rels, linkProcessToPythonEnv(st, envID, h, p, "")...)
		return ents, rels, envID, ""
	}
	if !fi.IsDir() {
		st.skip(root, "not_directory")
		return nil, nil, "", ""
	}

	inodeKey := inodeKeyOf(fi)
	if existing := st.envByRoot[root]; existing != "" {
		st.skip(root, "inode_dedup")
		rels = append(rels, linkProcessToPythonEnv(st, existing, h, p, st.envInterp[existing])...)
		return nil, rels, existing, ""
	}
	if inodeKey != "" {
		if existing := st.envByInode[inodeKey]; existing != "" {
			st.skip(root, "inode_dedup")
			st.envByRoot[root] = existing
			rels = append(rels, linkProcessToPythonEnv(st, existing, h, p, st.envInterp[existing])...)
			return nil, rels, existing, ""
		}
	}

	cfg := readPyvenvCfg(filepath.Join(root, "pyvenv.cfg"))
	interpPath := h.interpreter
	if interpPath == "" {
		interpPath = findInterpreterInEnv(root)
	}
	var interpID string
	if interpPath != "" {
		interpID, ents = ensurePythonInterpreter(st, ents, interpPath, p, cfg)
	}

	ownerUID := p.uid
	if uid := fileOwnerUID(fi); uid != 0 {
		ownerUID = uid
	}

	envRec := map[string]any{
		"entity_type":       "python_environment",
		"entity_id":         envID,
		"environment_root":  root,
		"kind":              kind,
		"scope":             h.scope,
		"discovery_source":  h.discovery,
		"interpreter_path":  nullIfEmpty(interpPath),
		"interpreter_id":    nullIfEmpty(interpID),
		"pyvenv_cfg":        cfg,
		"owner_uid":         ownerUID,
		"collection_status": "observed",
		"process_ids":       []int{},
	}
	st.envRecords[envID] = envRec
	st.envByRoot[root] = envID
	if inodeKey != "" {
		st.envByInode[inodeKey] = envID
	}
	st.envInterp[envID] = interpID
	ents = append(ents, envRec)
	st.coverage.Environments++
	st.coverage.EnvKinds[kind]++

	rels = append(rels, linkProcessToPythonEnv(st, envID, h, p, interpID)...)

	dists, derr := readDistributionsForEnv(st, root, kind, h.scope, envID)
	if derr != "" {
		errMsg = derr
	}
	for _, d := range dists {
		id := asString(d["entity_id"])
		if id == "" || st.seenDistID[id] {
			continue
		}
		ownRels := applyPythonDistOSOwnership(st, d)
		st.seenDistID[id] = true
		st.distRecords[id] = d
		ents = append(ents, d)
		ents = append(ents, ownRels...)
		st.distByEnv[envID] = append(st.distByEnv[envID], d)
		st.coverage.Distributions++
		if d["raw_version_string"] != nil && asString(d["name_normalized"]) != "" {
			st.coverage.PackagesCompleteIdentity++
		} else {
			st.coverage.PackagesUnknownVersion++
		}
		rid := "python_environment_contains_distribution:" + envID + ":" + id
		if !st.seenRel[rid] {
			st.seenRel[rid] = true
			rels = append(rels, rel("python_environment_contains_distribution", envID, id, "metadata"))
		}
	}
	return ents, rels, envID, errMsg
}

// linkProcessToPythonEnv always emits per-process relationships even when the
// environment/interpreter entities were previously deduplicated.
func linkProcessToPythonEnv(st *pythonScanState, envID string, h pythonEnvHint, p procSeed, interpID string) []map[string]any {
	if h.activeForPID <= 0 {
		return nil
	}
	var rels []map[string]any
	pid := h.activeForPID
	if env := st.envRecords[envID]; env != nil {
		env["process_ids"] = appendUniqueInt(asIntSlice(env["process_ids"]), pid)
	}
	if interpID == "" {
		interpID = st.envInterp[envID]
	}
	if interpID != "" {
		rid := "process_uses_python_interpreter:process:" + itoa(pid) + ":" + interpID
		if !st.seenRel[rid] {
			st.seenRel[rid] = true
			rels = append(rels, rel("process_uses_python_interpreter", "process:"+itoa(pid), interpID, "proc"))
		}
	}
	rid := "process_uses_python_environment:process:" + itoa(pid) + ":" + envID
	if !st.seenRel[rid] {
		st.seenRel[rid] = true
		rels = append(rels, rel("process_uses_python_environment", "process:"+itoa(pid), envID, h.discovery))
	}
	return rels
}

func appendUniqueInt(in []int, v int) []int {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func asIntSlice(v any) []int {
	switch t := v.(type) {
	case []int:
		return t
	case []any:
		var out []int
		for _, x := range t {
			switch n := x.(type) {
			case int:
				out = append(out, n)
			case float64:
				out = append(out, int(n))
			}
		}
		return out
	default:
		return nil
	}
}

func finalizePythonActiveCoverage(st *pythonScanState, activeEnvIDs map[string]bool) {
	// Active environment membership only contributes inventory coverage — never load proof.
	seenActiveDist := map[string]bool{}
	for envID := range activeEnvIDs {
		for _, d := range st.distByEnv[envID] {
			id := asString(d["entity_id"])
			if id == "" {
				continue
			}
			if !seenActiveDist[id] {
				seenActiveDist[id] = true
				st.coverage.DistributionsInActiveEnvs++
			}
			d["runtime_load_status"] = "installed_not_proven_loaded"
			d["loaded_by_process_ids"] = nil
			d["loaded_module_paths"] = nil
			d["runtime_detection_method"] = nil
			d["runtime_evidence_ids"] = nil
		}
	}

	type loadHit struct {
		pids  []int
		paths []string
		eids  []string
	}
	hits := map[string]*loadHit{}

	// 1–6: per-PID mapped extension → dpkg owner → OS package entity → Python distribution.
	for pid, mapped := range st.mappedFilesByPID {
		pathToDist := map[string]string{} // one mapped path → at most one distribution
		for _, path := range mapped {
			if !isPythonExtensionMappedPath(path) {
				continue
			}
			pkgName, ok := st.dpkg().ownerPackage(path)
			if !ok || pkgName == "" {
				continue
			}
			pkg, ok := st.dpkg().lookup(pkgName)
			if !ok {
				continue
			}
			osPkgID := pkg.EntityID()
			if osPkgID == "" {
				continue
			}
			distID := st.distByOSPkg[osPkgID]
			if distID == "" {
				continue
			}
			d := st.distRecords[distID]
			if d == nil {
				continue
			}
			// Path must be owned by this distribution's OS binary package (exact).
			if asString(d["os_binary_package"]) != pkgName {
				continue
			}
			if prev, claimed := pathToDist[path]; claimed && prev != distID {
				continue
			}
			pathToDist[path] = distID

			h := hits[distID]
			if h == nil {
				h = &loadHit{}
				hits[distID] = h
			}
			h.pids = appendUniqueInt(h.pids, pid)
			h.paths = appendUniqueString(h.paths, path)
			h.eids = appendUniqueString(h.eids, "runtime:proc_maps:"+itoa(pid)+":"+hashShort(path))

			rid := "process_loads_python_distribution:process:" + itoa(pid) + ":" + distID
			if !st.seenRel[rid] {
				st.seenRel[rid] = true
				st.pendingLoadRels = append(st.pendingLoadRels,
					rel("process_loads_python_distribution", "process:"+itoa(pid), distID, "proc_maps_dpkg_ownership"))
			}
		}
	}

	for distID, h := range hits {
		d := st.distRecords[distID]
		if d == nil || len(h.paths) == 0 {
			continue
		}
		d["runtime_load_status"] = "confirmed_loaded"
		d["loaded_by_process_ids"] = h.pids
		d["loaded_module_paths"] = h.paths
		d["runtime_detection_method"] = "proc_maps_dpkg_ownership"
		d["runtime_evidence_ids"] = h.eids
		st.coverage.DistributionsConfirmedLoaded++
	}
}

// isPythonExtensionMappedPath accepts native Python extension modules from maps.
// Shared site-/dist-packages directories alone are never load evidence.
func isPythonExtensionMappedPath(path string) bool {
	if path == "" || strings.HasSuffix(path, "/") {
		return false
	}
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".so") {
		return false
	}
	return strings.Contains(path, "dist-packages") ||
		strings.Contains(path, "site-packages") ||
		strings.Contains(path, "/lib/python")
}

func appendUniqueString(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

func pythonMappedFiles(mapsPath string) []string {
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		path = strings.TrimSuffix(path, " (deleted)")
		if path == "" || strings.HasPrefix(path, "[") {
			continue
		}
		if !isPythonExtensionMappedPath(path) {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
		if len(out) >= 500 {
			break
		}
	}
	return out
}

func ensurePythonInterpreter(st *pythonScanState, ents []map[string]any, path string, p procSeed, cfg map[string]string) (string, []map[string]any) {
	path = strings.TrimSuffix(filepath.Clean(path), " (deleted)")
	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}
	id := "python:interpreter:" + hashShort(resolved)
	if st.seenInterp[id] {
		return id, ents
	}
	st.seenInterp[id] = true

	upstream, verSource := resolveInterpreterUpstreamVersion(path, resolved, cfg)
	verStatus := ""
	var verAny any
	if upstream != "" {
		verAny = upstream
	} else {
		verAny = nil
		verStatus = "unknown_not_executed"
	}
	rec := map[string]any{
		"entity_type":               "python_interpreter",
		"entity_id":                 id,
		"interpreter_path":          path,
		"interpreter_path_resolved": resolved,
		"version":                   verAny,
		"upstream_version":          verAny,
		"version_source":            nullIfEmpty(verSource),
		"version_status":            nullIfEmpty(verStatus),
		"os_package_raw_version":    nil,
		"scope":                     scopeForPath(resolved),
		"discovery_source":          "process",
		"collection_status":         "observed",
		"owner_uid":                 p.uid,
	}
	ents = append(ents, rec)
	st.interpRecords[id] = rec
	st.coverage.Interpreters++

	idx := st.dpkg()
	pkgName := ""
	evidencePath := resolved
	if name, ok := idx.ownerPackage(resolved); ok {
		pkgName = name
	} else if name, ok := idx.ownerPackage(path); ok {
		pkgName = name
		evidencePath = path
	}
	if pkgName != "" {
		rec["os_package_name"] = pkgName
		rec["os_package_manager"] = "dpkg"
		rec["os_package_owner_status"] = "observed"
		rec["ownership_evidence_path"] = evidencePath
		if pkg, ok := idx.lookup(pkgName); ok {
			rec["os_package_raw_version"] = pkg.Version
			// Prefer exact upstream patch from OS package when binary name only had major.minor.
			if up := debianUpstreamPythonVersion(pkg.Version); up != "" {
				if verAny == nil || !hasPythonPatchLevel(asString(verAny)) {
					rec["version"] = up
					rec["upstream_version"] = up
					rec["version_source"] = "dpkg_upstream_version"
					rec["version_status"] = nil
				}
			}
			if osPkgID := pkg.EntityID(); osPkgID != "" {
				rid := "python_interpreter_belongs_to_os_package:" + id + ":" + osPkgID
				if !st.seenRel[rid] {
					st.seenRel[rid] = true
					ents = append(ents, rel("python_interpreter_belongs_to_os_package", id, osPkgID, "dpkg_file_list"))
				}
			}
		}
	}
	return id, ents
}

func resolveInterpreterUpstreamVersion(path, resolved string, cfg map[string]string) (ver, source string) {
	// Prefer full patch version from pyvenv.cfg when present.
	if cfg != nil {
		if v := strings.TrimSpace(cfg["version"]); v != "" {
			return normalizePythonUpstreamVersion(v), "pyvenv_cfg"
		}
	}
	if v := pythonVersionFromPath(path); v != "" {
		return v, "binary_name"
	}
	if v := pythonVersionFromPath(resolved); v != "" {
		return v, "binary_name_resolved"
	}
	return "", ""
}

func normalizePythonUpstreamVersion(v string) string {
	v = strings.TrimSpace(v)
	// Keep full X.Y.Z when available; strip trailing noise.
	fields := strings.Fields(v)
	if len(fields) > 0 {
		v = fields[0]
	}
	return v
}

func hasPythonPatchLevel(v string) bool {
	return strings.Count(v, ".") >= 2
}

func debianUpstreamPythonVersion(raw string) string {
	_, ver, _ := ParseDebianVersion(raw)
	ver = strings.TrimSpace(ver)
	if ver == "" {
		return ""
	}
	// python3.x packages use upstream X.Y.Z in the Debian version field.
	if strings.Count(ver, ".") >= 1 {
		return ver
	}
	return ""
}

// applyPythonDistOSOwnership uses the reused dpkg file/package index (not
// per-distribution dpkg-query -S). Never classifies dist-packages as PyPI
// solely from upstream METADATA version.
func applyPythonDistOSOwnership(st *pythonScanState, d map[string]any) []map[string]any {
	meta := asString(d["meta_path"])
	candidates := []string{meta}
	if meta != "" {
		dir := filepath.Dir(meta)
		candidates = append(candidates, dir)
		if recPath := filepath.Join(dir, "RECORD"); pathIsRegularFile(recPath) {
			candidates = append(candidates, recPath)
		}
		norm := asString(d["name_normalized"])
		mod := strings.ReplaceAll(norm, "-", "_")
		site := filepath.Dir(dir)
		candidates = append(candidates,
			filepath.Join(site, mod),
			filepath.Join(site, mod+".py"),
			filepath.Join(site, mod, "__init__.py"),
		)
	}

	idx := st.dpkg()
	var pkgName, evidencePath string
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if name, ok := idx.ownerPackage(cand); ok {
			pkgName = name
			evidencePath = cand
			break
		}
	}

	installer := asString(d["installer"])
	kind := asString(d["environment_kind"])

	if pkgName != "" {
		pkg, ok := idx.lookup(pkgName)
		d["installation_origin"] = "os_package"
		d["os_package_manager"] = "dpkg"
		d["os_binary_package"] = pkgName
		d["ownership_confidence"] = "direct"
		d["ownership_evidence_path"] = evidencePath
		d["resolver_ecosystem"] = "ubuntu_dpkg"
		if ok {
			d["os_source_package"] = nullIfEmpty(pkg.Source)
			d["os_package_version"] = nullIfEmpty(pkg.Version)
			osPkgID := pkg.EntityID()
			id := asString(d["entity_id"])
			if osPkgID != "" && id != "" {
				st.registerDistOSPackage(id, osPkgID)
				rid := "python_distribution_belongs_to_os_package:" + id + ":" + osPkgID
				if !st.seenRel[rid] {
					st.seenRel[rid] = true
					return []map[string]any{rel("python_distribution_belongs_to_os_package", id, osPkgID, "dpkg_file_list")}
				}
			}
		} else {
			d["os_source_package"] = nil
			d["os_package_version"] = nil
		}
		return nil
	}

	// Not owned by dpkg.
	d["os_package_manager"] = nil
	d["os_binary_package"] = nil
	d["os_source_package"] = nil
	d["os_package_version"] = nil
	d["ownership_confidence"] = "none"
	switch {
	case kind == "conda" || installer == "conda":
		d["installation_origin"] = "conda"
		d["resolver_ecosystem"] = "conda"
	case strings.Contains(meta, "/usr/lib/python") && strings.Contains(meta, "dist-packages"):
		d["installation_origin"] = "os_package_unconfirmed"
		d["resolver_ecosystem"] = "ubuntu_dpkg"
		d["ownership_confidence"] = "inferred_path_unconfirmed"
	case installer == "pip" || kind == "venv" || kind == "virtualenv" || kind == "pipx" || kind == "poetry" || kind == "user_site":
		d["installation_origin"] = "pip"
		d["resolver_ecosystem"] = "pypi"
	case strings.Contains(meta, "/usr/local/"):
		d["installation_origin"] = "pip"
		d["resolver_ecosystem"] = "pypi"
	default:
		d["installation_origin"] = "unknown"
		d["resolver_ecosystem"] = nil
	}
	return nil
}

func pathIsRegularFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func findInterpreterInEnv(root string) string {
	for _, name := range []string{"bin/python", "bin/python3", "bin/python3.12", "bin/python3.11", "bin/python3.10", "bin/python3.9"} {
		p := filepath.Join(root, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	// conda may use bin/python
	return ""
}

func readPyvenvCfg(path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func readDistributionsForEnv(st *pythonScanState, root, kind, scope, envID string) ([]map[string]any, string) {
	var out []map[string]any
	errMsg := ""

	switch kind {
	case "conda":
		found, e := readCondaMeta(st, root, scope, envID)
		out = append(out, found...)
		errMsg = e
	default:
		// site/dist-packages under lib/python*
		for _, site := range pythonSitePackageDirs(root, st.limits.maxDepth) {
			found, e := readSiteDistributions(st, site, kind, scope, envID)
			out = append(out, found...)
			if e != "" {
				errMsg = e
			}
			if len(out) >= maxPythonDistsPerEnv {
				out = out[:maxPythonDistsPerEnv]
				return out, "scan_limit"
			}
		}
		// user-site: ~/.local/lib/pythonX.Y/site-packages
		if kind == "user_site" {
			lib := filepath.Join(root, "lib")
			for _, site := range pythonSitePackageDirs(lib, st.limits.maxDepth) {
				found, e := readSiteDistributions(st, site, kind, scope, envID)
				out = append(out, found...)
				if e != "" {
					errMsg = e
				}
			}
		}
		// system: /usr/lib/pythonX.Y/{dist,site}-packages
		if kind == "system" {
			for _, pattern := range []string{
				filepath.Join(root, "lib", "python*"),
				filepath.Join(root, "lib", "python*", "dist-packages"),
				filepath.Join(root, "lib", "python*", "site-packages"),
				filepath.Join(root, "local", "lib", "python*", "dist-packages"),
			} {
				matches, _ := filepath.Glob(pattern)
				for _, m := range matches {
					stInfo, err := os.Stat(m)
					if err != nil || !stInfo.IsDir() {
						continue
					}
					base := filepath.Base(m)
					if strings.HasPrefix(base, "python") && !strings.Contains(m, "packages") {
						for _, sub := range []string{"dist-packages", "site-packages"} {
							site := filepath.Join(m, sub)
							found, e := readSiteDistributions(st, site, kind, scope, envID)
							out = append(out, found...)
							if e != "" {
								errMsg = e
							}
						}
						continue
					}
					found, e := readSiteDistributions(st, m, kind, scope, envID)
					out = append(out, found...)
					if e != "" {
						errMsg = e
					}
				}
			}
		}
	}
	return out, errMsg
}

func pythonSitePackageDirs(root string, maxDepth int) []string {
	var out []string
	// root may be env root (has lib/) or already lib/
	candidates := []string{
		filepath.Join(root, "lib"),
		root,
	}
	for _, lib := range candidates {
		entries, err := os.ReadDir(lib)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "python") {
				continue
			}
			for _, sub := range []string{"site-packages", "dist-packages"} {
				site := filepath.Join(lib, e.Name(), sub)
				if st, err := os.Stat(site); err == nil && st.IsDir() {
					out = append(out, site)
				}
			}
		}
	}
	_ = maxDepth
	return uniqueStrings(out)
}

func readSiteDistributions(st *pythonScanState, site, kind, scope, envID string) ([]map[string]any, string) {
	entries, err := os.ReadDir(site)
	if err != nil {
		st.skip(site, skipReasonFromPathError(err))
		return nil, ""
	}
	var out []map[string]any
	for _, e := range entries {
		if st.metaFiles >= st.limits.maxMetaFiles {
			return out, "scan_limit"
		}
		name := e.Name()
		path := filepath.Join(site, name)
		switch {
		case strings.HasSuffix(name, ".dist-info") && e.IsDir():
			st.metaFiles++
			if rec := parseDistInfo(path, kind, scope, envID); rec != nil {
				out = append(out, rec)
			} else {
				st.skip(path, "no_metadata")
				out = append(out, incompleteDist(path, kind, scope, envID, "no_metadata"))
			}
		case strings.HasSuffix(name, ".egg-info"):
			st.metaFiles++
			if rec := parseEggInfo(path, kind, scope, envID); rec != nil {
				out = append(out, rec)
			} else {
				st.skip(path, "no_metadata")
			}
		case strings.HasSuffix(name, ".egg-link") && !e.IsDir():
			st.metaFiles++
			if rec := parseEggLink(path, kind, scope, envID); rec != nil {
				out = append(out, rec)
			}
		}
		if len(out) >= maxPythonDistsPerEnv {
			return out, "scan_limit"
		}
	}
	return out, ""
}

func parseDistInfo(infoDir, kind, scope, envID string) map[string]any {
	metaPath := filepath.Join(infoDir, "METADATA")
	if _, err := os.Stat(metaPath); err != nil {
		return nil
	}
	name, ver := readNameVersionMetadata(metaPath)
	if name == "" {
		return nil
	}
	norm := pep503Normalize(name)
	rec := baseDistRec(name, norm, ver, kind, scope, envID, metaPath)
	rec["metadata_format"] = "dist-info"
	if b, err := os.ReadFile(filepath.Join(infoDir, "INSTALLER")); err == nil {
		rec["installer"] = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(infoDir, "direct_url.json")); err == nil {
		var du map[string]any
		if json.Unmarshal(b, &du) == nil {
			rec["direct_url"] = du
			rec["editable"] = isEditableDirectURL(du)
		}
	}
	if _, err := os.Stat(filepath.Join(infoDir, "RECORD")); err == nil {
		rec["record_present"] = true
	}
	return rec
}

func parseEggInfo(path, kind, scope, envID string) map[string]any {
	metaPath := path
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		metaPath = filepath.Join(path, "PKG-INFO")
	}
	name, ver := readNameVersionMetadata(metaPath)
	if name == "" {
		return nil
	}
	norm := pep503Normalize(name)
	rec := baseDistRec(name, norm, ver, kind, scope, envID, metaPath)
	rec["metadata_format"] = "egg-info"
	return rec
}

func parseEggLink(path, kind, scope, envID string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	target := strings.TrimSpace(strings.Split(string(b), "\n")[0])
	name := strings.TrimSuffix(filepath.Base(path), ".egg-link")
	norm := pep503Normalize(name)
	rec := baseDistRec(name, norm, "", kind, scope, envID, path)
	rec["metadata_format"] = "egg-link"
	rec["editable"] = true
	rec["editable_target"] = nullIfEmpty(target)
	rec["raw_version_string"] = nil
	rec["version_status"] = "unknown_editable_egg_link"
	return rec
}

func readCondaMeta(st *pythonScanState, root, scope, envID string) ([]map[string]any, string) {
	dir := filepath.Join(root, "conda-meta")
	entries, err := os.ReadDir(dir)
	if err != nil {
		st.skip(dir, skipReasonFromPathError(err))
		return nil, ""
	}
	var out []map[string]any
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if e.Name() == "history" {
			continue
		}
		if st.metaFiles >= st.limits.maxMetaFiles {
			return out, "scan_limit"
		}
		st.metaFiles++
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			st.skip(path, skipReasonFromPathError(err))
			continue
		}
		var meta map[string]any
		if json.Unmarshal(b, &meta) != nil {
			st.skip(path, "no_metadata")
			out = append(out, incompleteDist(path, "conda", scope, envID, "no_metadata"))
			continue
		}
		name := asString(meta["name"])
		ver := asString(meta["version"])
		if name == "" {
			st.skip(path, "no_metadata")
			continue
		}
		norm := pep503Normalize(name)
		rec := baseDistRec(name, norm, ver, "conda", scope, envID, path)
		rec["metadata_format"] = "conda-meta"
		rec["installer"] = "conda"
		rec["conda_build_string"] = meta["build"]
		out = append(out, rec)
		if len(out) >= maxPythonDistsPerEnv {
			return out, "scan_limit"
		}
	}
	return out, ""
}

func readNameVersionMetadata(path string) (string, string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	name, ver := "", ""
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Name: ") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
		} else if strings.HasPrefix(line, "Version: ") {
			ver = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}
		if name != "" && ver != "" {
			break
		}
	}
	return name, ver
}

func baseDistRec(name, norm, ver, kind, scope, envID, metaPath string) map[string]any {
	id := "python:dist:" + hashShort(envID+":"+norm+":"+ver)
	rec := map[string]any{
		"entity_type":          "python_distribution",
		"entity_id":            id,
		"scope":                scope,
		"environment_id":       envID,
		"environment_kind":     kind,
		"name":                 name,
		"name_raw":             name,
		"name_normalized":      norm,
		"raw_version_string":   nullIfEmpty(ver),
		"version":              nullIfEmpty(ver),
		"meta_path":            metaPath,
		"installer":            nil,
		"editable":             false,
		"direct_url":           nil,
		"discovery_source":     "metadata",
		"collection_status":    "observed",
		"installation_origin":  nil,
		"os_package_manager":   nil,
		"os_binary_package":    nil,
		"os_source_package":    nil,
		"os_package_version":   nil,
		"ownership_confidence": nil,
		"runtime_load_status":  "installed_not_proven_loaded",
		"resolver_ecosystem":   nil,
		"identity": map[string]any{
			"scope":           scope,
			"environment_id":  envID,
			"name_normalized": norm,
			"raw_version":     nullIfEmpty(ver),
		},
	}
	if ver == "" {
		rec["version_status"] = "unknown"
	}
	return rec
}

func incompleteDist(path, kind, scope, envID, reason string) map[string]any {
	id := "python:dist:" + hashShort(envID+":incomplete:"+path)
	return map[string]any{
		"entity_type":          "python_distribution",
		"entity_id":            id,
		"scope":                scope,
		"environment_id":       envID,
		"environment_kind":     kind,
		"name":                 nil,
		"name_normalized":      nil,
		"raw_version_string":   nil,
		"meta_path":            path,
		"collection_status":    "partial",
		"unavailable_reason":   reason,
		"discovery_source":     "metadata",
		"installation_origin":  nil,
		"os_package_manager":   nil,
		"os_binary_package":    nil,
		"os_source_package":    nil,
		"os_package_version":   nil,
		"ownership_confidence": nil,
		"runtime_load_status":  "installed_not_proven_loaded",
	}
}

func isEditableDirectURL(du map[string]any) bool {
	if du == nil {
		return false
	}
	if dir, ok := du["dir_info"].(map[string]any); ok {
		if ed, ok := dir["editable"].(bool); ok && ed {
			return true
		}
	}
	return false
}

func pep503Normalize(name string) string {
	return strings.ToLower(pep503Re.ReplaceAllString(strings.TrimSpace(name), "-"))
}

func inodeKeyOf(fi os.FileInfo) string {
	return fileInodeKey(fi)
}

func rel(typ, src, dst, evidence string) map[string]any {
	return map[string]any{
		"entity_type":       "relationship",
		"entity_id":         "rel:" + hashShort(typ+":"+src+":"+dst),
		"relationship":      typ,
		"source_entity_id":  src,
		"target_entity_id":  dst,
		"confidence":        "direct",
		"evidence_source":   evidence,
		"collection_status": "observed",
	}
}
