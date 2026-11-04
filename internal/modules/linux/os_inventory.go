package linux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

type OSInventory struct{}

func (m *OSInventory) ID() string          { return "os_inventory" }
func (m *OSInventory) Version() string     { return "1.2.0" }
func (m *OSInventory) Platforms() []string { return []string{"linux"} }

// Overridable in tests. Production order prefers modern os-release, then
// legacy lsb-release / debian_version used by older images (e.g. Metasploitable2).
var osReleasePaths = []string{
	"/etc/os-release",
	"/usr/lib/os-release",
}

var lsbReleasePath = "/etc/lsb-release"
var debianVersionPath = "/etc/debian_version"

func (m *OSInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	raw, source, err := loadDistroIdentity()
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", err.Error()))
		common.Finish(&res, started, "unavailable")
		return res
	}

	hostname, _ := os.Hostname()
	machineID := readTrim("/etc/machine-id")
	if machineID == "" {
		machineID = readTrim("/var/lib/dbus/machine-id")
	}
	kernel := readTrim("/proc/sys/kernel/osrelease")
	fqdn := readFQDN()
	rebootRequired, rebootPkgs := readRebootRequired()

	value := map[string]any{
		"distribution_name":        raw["NAME"],
		"distribution_id":          raw["ID"],
		"distribution_version":     raw["VERSION"],
		"version_id":               raw["VERSION_ID"],
		"version_codename":         raw["VERSION_CODENAME"],
		"variant":                  raw["VARIANT"],
		"pretty_name":              raw["PRETTY_NAME"],
		"kernel_version":           kernel,
		"architecture":             runtime.GOARCH,
		"hostname":                 hostname,
		"fqdn":                     fqdn,
		"machine_id":               machineID,
		"timezone":                 timezone(),
		"init_system":              detectInit(),
		"reboot_required":          rebootRequired,
		"reboot_required_packages": rebootPkgs,
	}
	rawOut := map[string]string{"source_file": source}
	for k, v := range raw {
		rawOut[k] = v
	}
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, rawOut))
	common.Finish(&res, started, "success")
	return res
}

// loadDistroIdentity returns normalized os-release-like keys plus the path used.
func loadDistroIdentity() (map[string]string, string, error) {
	var errs []string
	for _, path := range osReleasePaths {
		raw, err := readKeyValueFile(path)
		if err != nil {
			errs = append(errs, path+": "+err.Error())
			continue
		}
		if strings.TrimSpace(raw["ID"]) == "" && strings.TrimSpace(raw["NAME"]) == "" {
			errs = append(errs, path+": empty identity")
			continue
		}
		normalizeOsReleaseKeys(raw)
		return raw, path, nil
	}

	if raw, err := readKeyValueFile(lsbReleasePath); err == nil {
		mapped := mapLSBRelease(raw)
		if mapped["ID"] != "" || mapped["VERSION_ID"] != "" {
			return mapped, lsbReleasePath, nil
		}
		errs = append(errs, lsbReleasePath+": no DISTRIB_ID/DISTRIB_RELEASE")
	} else {
		errs = append(errs, lsbReleasePath+": "+err.Error())
	}

	if b, err := os.ReadFile(debianVersionPath); err == nil {
		ver := strings.TrimSpace(string(b))
		if ver != "" {
			return mapDebianVersion(ver), debianVersionPath, nil
		}
		errs = append(errs, debianVersionPath+": empty")
	} else {
		errs = append(errs, debianVersionPath+": "+err.Error())
	}

	return nil, "", fmt.Errorf("no distro identity files readable (%s)", strings.Join(errs, "; "))
}

func readKeyValueFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		raw[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return raw, nil
}

func normalizeOsReleaseKeys(raw map[string]string) {
	if id := strings.TrimSpace(raw["ID"]); id != "" {
		raw["ID"] = strings.ToLower(id)
	}
	if cn := strings.TrimSpace(raw["VERSION_CODENAME"]); cn != "" {
		raw["VERSION_CODENAME"] = strings.ToLower(cn)
	}
}

func mapLSBRelease(lsb map[string]string) map[string]string {
	id := strings.ToLower(strings.TrimSpace(lsb["DISTRIB_ID"]))
	release := strings.TrimSpace(lsb["DISTRIB_RELEASE"])
	codename := strings.ToLower(strings.TrimSpace(lsb["DISTRIB_CODENAME"]))
	desc := strings.TrimSpace(lsb["DISTRIB_DESCRIPTION"])

	version := desc
	if version == "" {
		switch {
		case release != "" && codename != "":
			version = release + " (" + codename + ")"
		case release != "":
			version = release
		}
	}
	pretty := desc
	if pretty == "" && id != "" && release != "" {
		pretty = titleWord(id) + " " + release
		if codename != "" {
			pretty += " (" + codename + ")"
		}
	}
	name := strings.TrimSpace(lsb["DISTRIB_ID"])
	if name == "" {
		name = id
	}

	out := map[string]string{
		"ID":               id,
		"NAME":             name,
		"VERSION":          version,
		"VERSION_ID":       release,
		"VERSION_CODENAME": codename,
		"PRETTY_NAME":      pretty,
	}
	for k, v := range lsb {
		out[k] = v
	}
	return out
}

func mapDebianVersion(ver string) map[string]string {
	// Strip suite suffixes like "lenny/sid".
	versionID := ver
	if i := strings.IndexAny(ver, "/ "); i >= 0 {
		versionID = ver[:i]
	}
	return map[string]string{
		"ID":          "debian",
		"NAME":        "Debian GNU/Linux",
		"VERSION":     ver,
		"VERSION_ID":  versionID,
		"PRETTY_NAME": "Debian GNU/Linux " + ver,
	}
}

func titleWord(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readFQDN() string {
	b, err := os.ReadFile("/etc/hostname")
	if err != nil {
		h, _ := os.Hostname()
		return h
	}
	return strings.TrimSpace(string(b))
}

func timezone() string {
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(link, "/zoneinfo/"); i >= 0 {
			return link[i+len("/zoneinfo/"):]
		}
	}
	return ""
}

func detectInit() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	return "unknown"
}

// Overridable in tests.
var rebootRequiredPath = "/var/run/reboot-required"
var rebootRequiredPkgsPath = "/var/run/reboot-required.pkgs"

// debianFamilyRebootSemantics is true when /etc/debian_version exists (Debian, Ubuntu, and derivatives).
// Only those hosts use /var/run/reboot-required; elsewhere the signal is unknown (null), not false.
func debianFamilyRebootSemantics() bool {
	_, err := os.Stat(debianVersionPath)
	return err == nil
}

// readRebootRequired observes /var/run/reboot-required (+ optional .pkgs) on Debian-family hosts only.
// Returns (required, pkgs): true/false on Debian-family; null/null on non-Debian or Stat error.
// All callers (os_inventory, kernel_inventory) share this — do not re-check distro at call sites.
func readRebootRequired() (any, any) {
	if !debianFamilyRebootSemantics() {
		return nil, nil
	}
	_, err := os.Stat(rebootRequiredPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return nil, nil
	}
	b, err := os.ReadFile(rebootRequiredPkgsPath)
	if err != nil {
		return true, nil
	}
	var pkgs []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			pkgs = append(pkgs, line)
		}
	}
	if len(pkgs) == 0 {
		return true, []string{}
	}
	return true, pkgs
}
