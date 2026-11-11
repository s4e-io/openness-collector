package linux

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/procutil"
	"github.com/s4e-io/openness-collector/internal/schema"
)

const maxLibsPerProcess = 80
const maxLibProcesses = 40

// LoadedLibraries maps listening processes to shared libraries via /proc/<pid>/maps.
type LoadedLibraries struct{}

func (m *LoadedLibraries) ID() string          { return "loaded_libraries" }
func (m *LoadedLibraries) Version() string     { return "1.0.0" }
func (m *LoadedLibraries) Platforms() []string { return []string{"linux"} }

func (m *LoadedLibraries) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	pids := listeningPIDs()
	if len(pids) == 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "no listening process PIDs for library mapping"))
		common.Finish(&res, started, "unavailable")
		return res
	}
	if len(pids) > maxLibProcesses {
		pids = pids[:maxLibProcesses]
		res.Errors = append(res.Errors, common.Err(m.ID(), "record_limit", "listening PID cap for library scan"))
	}

	ownerCache := map[string]map[string]any{}
	partial := false

	for _, pid := range pids {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "loaded_libraries cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}
		rec, errCode := collectProcessLibraries(ctx, pid, ownerCache)
		if errCode != "" {
			partial = true
			res.Errors = append(res.Errors, common.Err(m.ID(), errCode, "pid="+strconv.Itoa(pid)))
			if rec == nil {
				continue
			}
		}
		if rec != nil {
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
		}
	}

	status := "success"
	if partial {
		status = "partial"
	}
	if len(res.Evidence) == 0 {
		status = "unavailable"
	}
	common.Finish(&res, started, status)
	return res
}

func listeningPIDs() []int {
	inodeToPID := buildInodePIDMap()
	socks := collectListenSockets(inodeToPID)
	seen := map[int]bool{}
	var out []int
	for _, s := range socks {
		pid := asInt(s["pid"])
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		out = append(out, pid)
	}
	return out
}

func collectProcessLibraries(ctx context.Context, pid int, ownerCache map[string]map[string]any) (map[string]any, string) {
	proc, st, _ := readProcess(pid)
	if st != "observed" {
		if st == "not_found" || st == "race" {
			return nil, "process_exited"
		}
		return nil, "permission_denied"
	}
	exe := asString(proc["executable_realpath"])
	if exe == "" {
		exe = asString(proc["executable_path"])
	}

	mapsPath := "/proc/" + strconv.Itoa(pid) + "/maps"
	f, err := os.Open(mapsPath)
	if err != nil {
		if os.IsPermission(err) {
			return map[string]any{
				"entity_type":     "process_libraries",
				"entity_id":       "libs:process:" + strconv.Itoa(pid),
				"process_id":      pid,
				"executable_path": nullIfEmpty(exe),
				"status":          "permission_denied",
				"libraries":       []any{},
				"library_count":   0,
			}, "permission_denied"
		}
		if os.IsNotExist(err) {
			return nil, "process_exited"
		}
		return nil, "unavailable"
	}
	defer f.Close()

	var content strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		content.WriteString(sc.Text())
		content.WriteByte('\n')
	}
	libs, meta := parseProcMapsContent(content.String())
	if meta["statically_linked"] == true && len(libs) == 0 {
		return map[string]any{
			"entity_type":         "process_libraries",
			"entity_id":           "libs:process:" + strconv.Itoa(pid),
			"process_id":          pid,
			"executable_path":     nullIfEmpty(exe),
			"status":              "observed",
			"statically_linked":   true,
			"libraries":           []any{},
			"library_count":       0,
			"interesting":         []any{},
			"maps_pathname_count": meta["pathname_count"],
		}, ""
	}

	var outLibs []map[string]any
	var interesting []map[string]any
	truncated := false
	for i, libPath := range libs {
		if i >= maxLibsPerProcess {
			truncated = true
			break
		}
		deleted := strings.Contains(libPath, " (deleted)")
		clean := strings.TrimSuffix(libPath, " (deleted)")
		owner, ok := ownerCache[clean]
		if !ok {
			owner = PackageOwner(ctx, clean)
			ownerCache[clean] = owner
		}
		rec := map[string]any{
			"entity_type":          "shared_library",
			"entity_id":            "lib:" + hashShort(clean),
			"path":                 clean,
			"deleted":              deleted,
			"package_name":         owner["package_name"],
			"package_manager":      owner["package_manager"],
			"package_owner_status": owner["status"],
			"source_package":       nil,
			"raw_version_string":   nil,
		}
		if pkg := asString(owner["package_name"]); pkg != "" && owner["package_manager"] == "dpkg" {
			src, ver := dpkgSourceOf(ctx, pkg)
			rec["source_package"] = nullIfEmpty(src)
			if ver != nil {
				rec["source_version"] = ver
			}
			if v := dpkgVersionOf(ctx, pkg); v != "" {
				rec["raw_version_string"] = v
			}
		}
		outLibs = append(outLibs, rec)
		if isInterestingLibrary(clean) {
			interesting = append(interesting, rec)
		}
	}

	errCode := ""
	if truncated {
		errCode = "record_limit"
	}

	return map[string]any{
		"entity_type":       "process_libraries",
		"entity_id":         "libs:process:" + strconv.Itoa(pid),
		"process_id":        pid,
		"executable_path":   nullIfEmpty(exe),
		"status":            "observed",
		"statically_linked": meta["statically_linked"] == true && len(outLibs) == 0,
		"libraries":         outLibs,
		"library_count":     len(outLibs),
		"interesting":       interesting,
		"interesting_count": len(interesting),
		"deleted_count":     countDeleted(outLibs),
		"relationships": []map[string]any{{
			"type":             "process_loads_libraries",
			"source_entity_id": "process:" + strconv.Itoa(pid),
			"target_count":     len(outLibs),
			"confidence":       "direct",
			"evidence_source":  "/proc/pid/maps",
		}},
	}, errCode
}

func parseProcMapsContent(content string) ([]string, map[string]any) {
	seen := map[string]bool{}
	var paths []string
	pathnameCount := 0
	soCount := 0
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if path == "" || strings.HasPrefix(path, "[") {
			continue
		}
		pathnameCount++
		base := filepath.Base(strings.TrimSuffix(path, " (deleted)"))
		if !strings.Contains(strings.ToLower(base), ".so") {
			continue
		}
		soCount++
		if seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	meta := map[string]any{
		"pathname_count": pathnameCount,
		"so_count":       soCount,
	}
	if soCount == 0 && pathnameCount <= 2 {
		meta["statically_linked"] = true
	}
	return paths, meta
}

func isInterestingLibrary(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSuffix(path, " (deleted)")))
	needles := []string{
		"libc.so", "libc-", "ld-linux", "libssl.so", "libcrypto.so", "libcurl.so",
		"libxml2.so", "libxslt.so", "libz.so", "liblzma.so", "libbz2.so",
		"libssl3.so", "libnss", "libpython", "libjvm", "libsqlite",
	}
	for _, n := range needles {
		if strings.Contains(base, n) {
			return true
		}
	}
	return false
}

func countDeleted(libs []map[string]any) int {
	n := 0
	for _, l := range libs {
		if l["deleted"] == true {
			n++
		}
	}
	return n
}

func dpkgVersionOf(ctx context.Context, pkg string) string {
	cmd := procutil.Command(ctx, "dpkg-query", "-W", "-f=${Version}", pkg)
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
