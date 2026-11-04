package linux

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

type Packages struct{}

func (m *Packages) ID() string          { return "packages" }
func (m *Packages) Version() string     { return "1.4.0" }
func (m *Packages) Platforms() []string { return []string{"linux"} }

func (m *Packages) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	if _, err := exec.LookPath("dpkg-query"); err == nil {
		collectDPKG(ctx, &res, m.ID())
		enrichPackagesWithAptLists(&res)
	}
	if _, err := exec.LookPath("rpm"); err == nil && rpmDatabasePresent(rpmDBPaths) {
		collectRPM(ctx, &res, m.ID())
	}
	if _, err := os.Stat(apkInstalledPath); err == nil {
		collectAPK(&res, m.ID(), apkInstalledPath)
	}
	if len(res.Evidence) == 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "no supported package manager found"))
		common.Finish(&res, started, "unavailable")
		return res
	}
	status := "success"
	if len(res.Errors) > 0 {
		status = "partial"
	}
	common.Finish(&res, started, status)
	return res
}

// dpkgStatusPath is overridable in tests.
var dpkgStatusPath = "/var/lib/dpkg/status"

func collectDPKG(ctx context.Context, res *schema.ModuleResult, moduleID string) {
	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Source}\n")
	out, err := cmd.Output()
	if err == nil {
		appendDPKGQueryLines(res, moduleID, string(out))
		return
	}
	res.Errors = append(res.Errors, common.Err(moduleID, "PACKAGE_DB_LOCKED", "dpkg-query: "+err.Error()))
	// Fallback for broken/emulated userspace (e.g. pipe2 ENOSYS on old Metasploitable).
	n, ferr := appendDPKGStatusFile(res, moduleID, dpkgStatusPath)
	if ferr != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "unavailable", "dpkg status fallback: "+ferr.Error()))
		return
	}
	if n == 0 {
		res.Errors = append(res.Errors, common.Err(moduleID, "partial", "dpkg status fallback produced 0 installed packages"))
		return
	}
	res.Errors = append(res.Errors, common.Err(moduleID, "partial", "used /var/lib/dpkg/status fallback after dpkg-query failure"))
}

func appendDPKGQueryLines(res *schema.ModuleResult, moduleID, out string) {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			continue
		}
		srcRaw := ""
		if len(parts) > 4 {
			srcRaw = parts[4]
		}
		appendDPKGPackage(res, moduleID, parts[0], parts[1], parts[2], parts[3], srcRaw, "dpkg-query", map[string]string{
			"raw_line":   line,
			"source_raw": srcRaw,
		})
	}
}

func appendDPKGStatusFile(res *schema.ModuleResult, moduleID, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return appendDPKGStatus(res, moduleID, f)
}

func appendDPKGStatus(res *schema.ModuleResult, moduleID string, r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	fields := map[string]string{}
	flush := func() int {
		name := fields["Package"]
		status := fields["Status"]
		if name == "" || !dpkgStatusInstalled(status) {
			fields = map[string]string{}
			return 0
		}
		arch := fields["Architecture"]
		if arch == "" {
			arch = "unknown"
		}
		ver := fields["Version"]
		srcRaw := fields["Source"]
		appendDPKGPackage(res, moduleID, name, ver, arch, status, srcRaw, "dpkg-status", map[string]string{
			"source_raw": srcRaw,
			"status_raw": status,
		})
		fields = map[string]string{}
		return 1
	}
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			n += flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation of previous field (Description, Conffiles, …) — ignore.
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	n += flush()
	if err := sc.Err(); err != nil {
		return n, err
	}
	return n, nil
}

func dpkgStatusInstalled(status string) bool {
	// Typical: "install ok installed". Reject config-files / not-installed.
	parts := strings.Fields(status)
	if len(parts) < 3 {
		return false
	}
	return parts[0] == "install" && parts[2] == "installed"
}

func appendDPKGPackage(res *schema.ModuleResult, moduleID, name, rawVersion, arch, status, srcRaw, evidenceSource string, raw map[string]string) {
	epoch, ver, rel := ParseDebianVersion(rawVersion)
	srcName, srcVer := ParseDebianSource(srcRaw)
	if srcName == "" {
		srcName = name
	}
	value := map[string]any{
		"entity_id":                 "pkg:dpkg:" + name + ":" + arch + ":" + rawVersion,
		"entity_type":               "package",
		"name":                      name,
		"source_package":            nullIfEmpty(srcName),
		"source_version":            srcVer,
		"epoch":                     epoch,
		"version":                   nullIfEmpty(ver),
		"release":                   nullIfEmpty(rel),
		"raw_version_string":        rawVersion,
		"architecture":              arch,
		"package_manager":           "dpkg",
		"package_status":            status,
		"vendor":                    nil,
		"repository_id":             nil,
		"repository_name":           nil,
		"repository_url":            nil,
		"repository_component":      nil,
		"repository_suite":          nil,
		"repository_origin":         nil,
		"repository_label":          nil,
		"installed_from_repository": nil,
		"install_time":              nil,
		"package_database_path":     "/var/lib/dpkg/status",
	}
	rels := []map[string]any{}
	if srcRaw != "" && srcName != "" && srcName != name {
		rels = append(rels, map[string]any{
			"type":             "package_built_from_source_package",
			"target_entity_id": "srcpkg:dpkg:" + srcName,
			"confidence":       "direct",
			"evidence_source":  "dpkg:Source",
		})
	} else if srcRaw == "" {
		rels = append(rels, map[string]any{
			"type":             "package_built_from_source_package",
			"target_entity_id": "srcpkg:dpkg:" + name,
			"confidence":       "inferred",
			"evidence_source":  "binary_name_fallback",
		})
		value["source_package"] = name
	} else if srcName == name {
		rels = append(rels, map[string]any{
			"type":             "package_built_from_source_package",
			"target_entity_id": "srcpkg:dpkg:" + srcName,
			"confidence":       "direct",
			"evidence_source":  "dpkg:Source",
		})
	}
	value["relationships"] = rels
	if raw == nil {
		raw = map[string]string{}
	}
	raw["collection_source"] = evidenceSource
	res.Evidence = append(res.Evidence, common.Evidence("native", moduleID, "observed", value, raw))
}

// rpmDBPaths are the system rpm databases (BerkeleyDB, NDB, SQLite; legacy
// and sysimage locations).
var rpmDBPaths = []string{
	"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/var/lib/rpm/Packages.db",
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages", "/usr/lib/sysimage/rpm/Packages.db",
}

// rpmDatabasePresent gates `rpm -qa`. On dpkg hosts the rpm tool is often
// installed without a system database and then falls back to ~/.rpmdb,
// creating SQLite files there: a host write the collector must not cause.
func rpmDatabasePresent(paths []string) bool {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func collectRPM(ctx context.Context, res *schema.ModuleResult, moduleID string) {
	format := "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\t%{SOURCERPM}\n"
	cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", format)
	out, err := cmd.Output()
	if err != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "PACKAGE_DB_LOCKED", "rpm: "+err.Error()))
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Split(line, "\t")
		if len(parts) < 5 {
			continue
		}
		epoch := parts[1]
		var epochVal any = epoch
		if epoch == "(none)" || epoch == "" {
			epochVal = nil
			epoch = "0"
		}
		rawVersion := parts[2] + "-" + parts[3]
		if epochVal != nil {
			rawVersion = epoch + ":" + rawVersion
		}
		srcRPM := ""
		if len(parts) > 7 {
			srcRPM = parts[7]
		}
		srcName, srcVer, srcRel, ok := ParseSourceRPM(srcRPM)
		value := map[string]any{
			"entity_id":                 "pkg:rpm:" + parts[0] + ":" + parts[4] + ":" + rawVersion,
			"entity_type":               "package",
			"name":                      parts[0],
			"epoch":                     epochVal,
			"version":                   parts[2],
			"release":                   parts[3],
			"raw_version_string":        rawVersion,
			"architecture":              parts[4],
			"package_manager":           "rpm",
			"package_status":            "installed",
			"vendor":                    nullIfEmpty(get(parts, 5)),
			"install_time":              nullIfEmpty(get(parts, 6)),
			"source_package":            nil,
			"source_version":            nil,
			"repository_id":             nil,
			"repository_name":           nil,
			"repository_url":            nil,
			"repository_component":      nil,
			"repository_suite":          nil,
			"repository_origin":         nil,
			"repository_label":          nil,
			"installed_from_repository": nil,
			"package_database_path":     "/var/lib/rpm",
		}
		rels := []map[string]any{}
		if ok {
			value["source_package"] = srcName
			value["source_version"] = srcVer + "-" + srcRel
			rels = append(rels, map[string]any{
				"type":             "package_built_from_source_package",
				"target_entity_id": "srcpkg:rpm:" + srcName,
				"confidence":       "direct",
				"evidence_source":  "rpm:SOURCERPM",
			})
		} else if srcRPM != "" {
			value["source_package"] = srcRPM
			rels = append(rels, map[string]any{
				"type":             "package_built_from_source_package",
				"target_entity_id": "srcpkg:rpm:" + srcRPM,
				"confidence":       "inferred",
				"evidence_source":  "rpm:SOURCERPM_unparsed",
			})
		}
		value["relationships"] = rels
		res.Evidence = append(res.Evidence, common.Evidence("native", moduleID, "observed", value, map[string]string{
			"raw_line":  line,
			"sourcerpm": srcRPM,
		}))
	}
}

// apkInstalledPath is overridable in tests.
var apkInstalledPath = "/lib/apk/db/installed"

// collectAPK reads the apk installed database directly (no apk binary), so it
// also works on minimal Alpine hosts.
func collectAPK(res *schema.ModuleResult, moduleID, path string) {
	f, err := os.Open(path)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "unavailable", "apk installed db: "+err.Error()))
		return
	}
	defer f.Close()
	pkgs, err := parseAPKDB(f, 0)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "partial", "apk installed db: "+err.Error()))
	}
	for _, p := range pkgs {
		appendAPKPackage(res, moduleID, p, path)
	}
}

func appendAPKPackage(res *schema.ModuleResult, moduleID string, p apkPackage, dbPath string) {
	arch := p.Arch
	if arch == "" {
		arch = "unknown"
	}
	ver, rel := splitAPKVersion(p.Version)
	value := map[string]any{
		"entity_id":                 "pkg:apk:" + p.Name + ":" + arch + ":" + p.Version,
		"entity_type":               "package",
		"name":                      p.Name,
		"source_package":            p.Name,
		"source_version":            nil,
		"epoch":                     nil,
		"version":                   nullIfEmpty(ver),
		"release":                   nullIfEmpty(rel),
		"raw_version_string":        p.Version,
		"architecture":              arch,
		"package_manager":           "apk",
		"package_status":            "installed",
		"vendor":                    nil,
		"repository_id":             nil,
		"repository_name":           nil,
		"repository_url":            nil,
		"repository_component":      nil,
		"repository_suite":          nil,
		"repository_origin":         nil,
		"repository_label":          nil,
		"installed_from_repository": nil,
		"install_time":              nil,
		"package_database_path":     dbPath,
	}
	// The apk origin (o:) is the source package secdb advisories are keyed on.
	srcRel := map[string]any{
		"type":             "package_built_from_source_package",
		"target_entity_id": "srcpkg:apk:" + p.Name,
		"confidence":       "inferred",
		"evidence_source":  "binary_name_fallback",
	}
	if p.Origin != "" {
		value["source_package"] = p.Origin
		srcRel["target_entity_id"] = "srcpkg:apk:" + p.Origin
		srcRel["confidence"] = "direct"
		srcRel["evidence_source"] = "apk:origin"
	}
	value["relationships"] = []map[string]any{srcRel}
	res.Evidence = append(res.Evidence, common.Evidence("native", moduleID, "observed", value, map[string]string{
		"collection_source": "apk-installed-db",
		"origin_raw":        p.Origin,
	}))
}

func get(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

func enrichPackagesWithAptLists(res *schema.ModuleResult) {
	idx := loadAptPackageOrigins()
	if idx == nil || len(idx.ByNVRA) == 0 {
		res.Errors = append(res.Errors, common.Err("packages", "partial", "apt lists unavailable; repository origin left unknown"))
		for i := range res.Evidence {
			v, ok := res.Evidence[i].Value.(map[string]any)
			if !ok || v["package_manager"] != "dpkg" {
				continue
			}
			v["highest_list_version"] = nil
			v["highest_list_origin"] = nil
			v["lists_updated_at"] = nil
			v["apt_update_success_at"] = readAptUpdateSuccessAt()
			res.Evidence[i].Value = v
		}
		return
	}
	matched := 0
	for i := range res.Evidence {
		v, ok := res.Evidence[i].Value.(map[string]any)
		if !ok {
			continue
		}
		if v["package_manager"] != "dpkg" {
			continue
		}
		applyAptOriginToPackage(v, idx)
		if v["installed_from_repository"] == true {
			matched++
		}
		res.Evidence[i].Value = v
	}
	if matched == 0 {
		res.Errors = append(res.Errors, common.Err("packages", "partial", "no installed packages matched apt lists"))
	}
}
