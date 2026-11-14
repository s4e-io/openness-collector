package linux

import (
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
func (m *Packages) Version() string     { return "1.6.0" }
func (m *Packages) Platforms() []string { return []string{"linux"} }

func (m *Packages) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	dbFound := false
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		dbFound = true
		collectDPKG(ctx, &res, m.ID())
		enrichPackagesWithAptLists(&res)
	} else if st, err := os.Stat(dpkgStatusPath); err == nil && st.Mode().IsRegular() {
		// dpkg database without the dpkg tools (minimal images).
		dbFound = true
		if _, err := appendDPKGStatusFile(&res, m.ID(), dpkgStatusPath); err != nil {
			res.Errors = append(res.Errors, common.Err(m.ID(), "partial", "dpkg status: "+err.Error()))
		}
	}
	if st, err := os.Stat(dpkgStatusDDir); err == nil && st.IsDir() {
		dbFound = true
		collectDPKGStatusD(&res, m.ID(), dpkgStatusDDir)
	}
	if _, err := exec.LookPath("rpm"); err == nil && rpmDatabasePresent(rpmDBPaths) {
		dbFound = true
		collectRPM(ctx, &res, m.ID())
	}
	if _, err := os.Stat(apkInstalledPath); err == nil {
		dbFound = true
		collectAPK(&res, m.ID(), apkInstalledPath)
	}
	if len(res.Evidence) == 0 {
		// Zero packages is never a clean result: downstream must not read an
		// empty inventory as a host without vulnerable packages.
		msg := "no supported package manager found"
		if dbFound {
			msg = "package database found but no installed packages were read"
		}
		res.Errors = append(res.Errors, common.Err(m.ID(), "no_packages", msg))
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
	before := len(res.Evidence)
	_, err := streamCommandLines(ctx, func(line string) bool {
		return appendDPKGQueryLine(res, moduleID, line)
	}, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Source}\t${Maintainer}\n")
	if err == nil {
		return
	}
	if ctx.Err() != nil {
		// Keep what was read before the deadline.
		res.Errors = append(res.Errors, common.Err(moduleID, "timeout", "dpkg-query: "+err.Error()))
		return
	}
	// Drop rows from a failed run so the fallback does not duplicate them.
	res.Evidence = res.Evidence[:before]
	res.Truncated = false
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

// appendDPKGQueryLine adds one dpkg-query row; false means the package limit
// was reached and reading should stop.
func appendDPKGQueryLine(res *schema.ModuleResult, moduleID, line string) bool {
	parts := strings.Split(line, "\t")
	if len(parts) < 4 {
		return true
	}
	if !hostPackageRoom(res, moduleID) {
		return false
	}
	srcRaw := ""
	if len(parts) > 4 {
		srcRaw = parts[4]
	}
	appendDPKGPackage(res, moduleID, parts[0], parts[1], parts[2], parts[3], srcRaw, get(parts, 5), "dpkg-query", map[string]string{
		"raw_line":   line,
		"source_raw": srcRaw,
	})
	return true
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
	n := 0
	err := scanDpkgStanzas(r, func(fields map[string]string) bool {
		if !dpkgStanzaInstalled(fields, false) {
			return true
		}
		if !hostPackageRoom(res, moduleID) {
			return false
		}
		appendDPKGStanza(res, moduleID, fields, "dpkg-status")
		n++
		return true
	})
	return n, err
}

// collectDPKGStatusD reads distroless-style /var/lib/dpkg/status.d stanzas.
func collectDPKGStatusD(res *schema.ModuleResult, moduleID, dir string) {
	err := scanDpkgStatusD(dir, func(fields map[string]string) bool {
		if !hostPackageRoom(res, moduleID) {
			return false
		}
		appendDPKGStanza(res, moduleID, fields, "dpkg-status.d")
		if v, ok := res.Evidence[len(res.Evidence)-1].Value.(map[string]any); ok {
			v["package_database_path"] = dir
		}
		return true
	})
	if err != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "partial", "dpkg status.d: "+err.Error()))
	}
}

func appendDPKGStanza(res *schema.ModuleResult, moduleID string, fields map[string]string, evidenceSource string) {
	arch := fields["Architecture"]
	if arch == "" {
		arch = "unknown"
	}
	status := fields["Status"]
	if status == "" {
		status = "install ok installed"
	}
	srcRaw := fields["Source"]
	appendDPKGPackage(res, moduleID, fields["Package"], fields["Version"], arch, status, srcRaw, fields["Maintainer"], evidenceSource, map[string]string{
		"source_raw": srcRaw,
		"status_raw": fields["Status"],
	})
}

func dpkgStatusInstalled(status string) bool {
	// Typical: "install ok installed". Reject config-files / not-installed.
	parts := strings.Fields(status)
	if len(parts) < 3 {
		return false
	}
	return parts[0] == "install" && parts[2] == "installed"
}

func appendDPKGPackage(res *schema.ModuleResult, moduleID, name, rawVersion, arch, status, srcRaw, maintainer, evidenceSource string, raw map[string]string) {
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
		"origin":                    packageOrigin("", "", maintainer, originBasisDpkgMaintainer),
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
	format := "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{INSTALLTIME}\t%{SOURCERPM}\t%{PACKAGER}\t%{RSAHEADER:pgpsig}\t%{SIGPGP:pgpsig}\n"
	_, err := streamCommandLines(ctx, func(line string) bool {
		return appendRPMLine(res, moduleID, line)
	}, "rpm", "-qa", "--qf", format)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "PACKAGE_DB_LOCKED", "rpm: "+err.Error()))
	}
}

// appendRPMLine adds one rpm -qa row; false means the package limit was
// reached and reading should stop.
func appendRPMLine(res *schema.ModuleResult, moduleID, line string) bool {
	parts := strings.Split(line, "\t")
	if len(parts) < 5 {
		return true
	}
	if !hostPackageRoom(res, moduleID) {
		return false
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
		"origin":                    packageOrigin(get(parts, 5), originBasisRPMVendor, get(parts, 8), originBasisRPMPackager),
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
	setOriginSigningKey(value, get(parts, 9), get(parts, 10))
	res.Evidence = append(res.Evidence, common.Evidence("native", moduleID, "observed", value, map[string]string{
		"raw_line":  line,
		"sourcerpm": srcRPM,
	}))
	return true
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
	// One past the limit so a cut is detectable.
	pkgs, err := parseAPKDB(f, hostPackageLimit+1)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(moduleID, "partial", "apk installed db: "+err.Error()))
	}
	for _, p := range pkgs {
		if !hostPackageRoom(res, moduleID) {
			break
		}
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
		"origin":                    packageOrigin("", "", p.Maintainer, originBasisAPKMaintainer),
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
