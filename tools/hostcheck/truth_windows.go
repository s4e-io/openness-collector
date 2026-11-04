//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/s4e-io/openness-collector/internal/schema"
)

var expectedModules = []string{
	"os_inventory", "hardware_inventory", "applications", "windows_features", "cbs_packages",
	"patches", "missing_updates", "language_deps", "services", "processes", "listening_ports", "evidence_chain",
	"security_products", "security_configuration", "users", "network_inventory", "software_inventory",
}

// Applications the windows-latest runner image ships; at least two must be found.
var knownApps = []*regexp.Regexp{
	regexp.MustCompile(`^Git$|^Git version`),
	regexp.MustCompile(`^Google Chrome$`),
	regexp.MustCompile(`^Mozilla Firefox`),
	regexp.MustCompile(`^7-Zip`),
	regexp.MustCompile(`^CMake$`),
	regexp.MustCompile(`^PowerShell 7`),
}

func powershell(script string) ([]byte, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		return out, fmt.Errorf("%v: %s", err, ee.Stderr)
	}
	return out, err
}

// psRows runs a script ending in ConvertTo-Json and always returns a list.
func psRows(script string) ([]map[string]any, error) {
	out, err := powershell(script)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" || s == "null" {
		return nil, nil
	}
	var rows []map[string]any
	if strings.HasPrefix(s, "[") {
		err = json.Unmarshal([]byte(s), &rows)
	} else {
		var one map[string]any
		err = json.Unmarshal([]byte(s), &one)
		rows = []map[string]any{one}
	}
	return rows, err
}

func (c *checker) hostTruth(doc *schema.Document) {
	osv := asMap(doc.OperatingSystem)
	if !c.check("truth/os-inventory-present", osv != nil, "operating_system object") {
		return
	}
	rows, err := psRows(`Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json -Compress`)
	if c.check("truth/cim-os", err == nil && len(rows) == 1, "err=%v rows=%d", err, len(rows)) {
		cim := rows[0]
		var bad []string
		for _, p := range [][2]string{{"Caption", "product_name"}, {"Version", "version"}, {"BuildNumber", "build_number"}} {
			if got, want := strings.TrimSpace(str(osv, p[1])), strings.TrimSpace(str(cim, p[0])); got != want {
				bad = append(bad, fmt.Sprintf("%s=%q cim %s=%q", p[1], got, p[0], want))
			}
		}
		c.check("truth/os-caption-version-build", len(bad) == 0, "caption=%q version=%s build=%s %v",
			str(cim, "Caption"), str(cim, "Version"), str(cim, "BuildNumber"), bad)
		c.check("truth/os-distribution", str(osv, "distribution_id") == "windows" && str(osv, "pretty_name") == strings.TrimSpace(str(cim, "Caption")),
			"distribution_id=%q pretty_name=%q", str(osv, "distribution_id"), str(osv, "pretty_name"))
	}

	host := os.Getenv("COMPUTERNAME")
	c.check("truth/hostname", strings.EqualFold(doc.Asset.Hostname, host), "asset=%q COMPUTERNAME=%q", doc.Asset.Hostname, host)
	arch := normArch(os.Getenv("PROCESSOR_ARCHITECTURE"))
	c.check("truth/architecture", doc.Asset.Architecture == arch && str(osv, "architecture") == arch,
		"asset=%q os=%q PROCESSOR_ARCHITECTURE=%q", doc.Asset.Architecture, str(osv, "architecture"), os.Getenv("PROCESSOR_ARCHITECTURE"))

	c.checkHotfixes(doc)
	c.checkApplications(doc)
	c.checkListener(doc)
	c.checkUser(doc)
}

func (c *checker) checkHotfixes(doc *schema.Document) {
	out, err := powershell(`Get-HotFix | ForEach-Object { $_.HotFixID }`)
	if !c.check("truth/get-hotfix", err == nil, "%v", err) {
		return
	}
	want := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			want[strings.ToUpper(l)] = true
		}
	}
	have := map[string]bool{}
	for _, v := range values(doc.Patches) {
		have[strings.ToUpper(str(v, "hotfix_id"))] = true
	}
	missing, extra := setDiff(want, have), setDiff(have, want)
	c.check("truth/hotfixes", len(missing) == 0 && len(extra) == 0,
		"collector=%d Get-HotFix=%d ids=[%s] missing=[%s] extra=[%s]", len(have), len(want), sample(keys(want), 8), sample(missing, 5), sample(extra, 5))
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hostApps reads the machine uninstall registry (64 and 32 bit views).
func hostApps() ([]map[string]any, error) {
	return psRows(`$p = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
  [PSCustomObject]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; key = [string]$_.PSChildName }
} | ConvertTo-Json -Compress`)
}

func (c *checker) checkApplications(doc *schema.Document) {
	truth, err := hostApps()
	if !c.check("truth/uninstall-registry", err == nil && len(truth) > 0, "entries=%d err=%v", len(truth), err) {
		return
	}
	have := map[string]bool{}
	for _, v := range values(doc.Applications) {
		have[str(v, "product_name")+"|"+str(v, "display_version")] = true
	}
	want := map[string]bool{}
	for _, t := range truth {
		want[str(t, "name")+"|"+str(t, "version")] = true
	}
	missing := setDiff(want, have)
	c.check("truth/applications", len(missing) == 0, "collector=%d registry=%d missing=[%s]", len(doc.Applications), len(want), sample(missing, 5))

	var found []string
	bad := 0
	for _, re := range knownApps {
		for _, t := range truth {
			name, ver := str(t, "name"), str(t, "version")
			if !re.MatchString(name) {
				continue
			}
			ok := have[name+"|"+ver] && ver != ""
			if !ok {
				bad++
			}
			found = append(found, fmt.Sprintf("%s %s ok=%v", name, ver, ok))
			break
		}
	}
	c.check("truth/known-applications", len(found) >= 2 && bad == 0, "%s", strings.Join(found, "; "))

	// Git's uninstall version must agree with the git binary itself.
	if out, err := exec.Command("git", "--version").Output(); err == nil {
		gv := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "git version "))
		var appVer string
		for _, v := range values(doc.Applications) {
			if regexp.MustCompile(`^Git$|^Git version`).MatchString(str(v, "product_name")) {
				appVer = str(v, "display_version")
				break
			}
		}
		base := strings.SplitN(gv, ".windows", 2)[0]
		c.check("truth/git-version", appVer != "" && strings.HasPrefix(appVer, base), "applications Git=%q git --version=%q", appVer, gv)
	}
}

func (c *checker) checkListener(doc *schema.Document) {
	var found map[string]any
	for _, v := range values(doc.ListeningPorts) {
		if num(v, "local_port") == c.opts.port && str(v, "protocol") == "tcp" {
			found = v
			break
		}
	}
	if !c.check("truth/listening-port", found != nil, "tcp port %d in listening_ports (%d sockets)", c.opts.port, len(doc.ListeningPorts)) {
		return
	}
	c.check("truth/listening-port-detail", str(found, "local_address") == "127.0.0.1" && num(found, "owning_pid") == os.Getpid(),
		"local_address=%s owning_pid=%d want pid=%d", str(found, "local_address"), num(found, "owning_pid"), os.Getpid())
}

func (c *checker) checkUser(doc *schema.Document) {
	found := false
	for _, v := range values(doc.Users) {
		if strings.EqualFold(str(v, "Name"), c.opts.user) {
			found = true
		}
	}
	c.check("truth/user", found && c.opts.user != "", "user %q among %d local users", c.opts.user, len(doc.Users))
}

// platformExtras runs the Windows-only collect inputs: --registry-values and --file-probes.
func (c *checker) platformExtras() {
	reg := []map[string]any{{"key": `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "name": "CurrentBuild"}}
	probes := []map[string]any{{"id": "hostcheck-git", "name": `^Git$|^Git version`, "path": `cmd\git.exe`, "base": "install_location"}}
	probeFile := c.path("probes.json")
	b, _ := json.Marshal(probes)
	_ = os.WriteFile(probeFile, b, 0o600)

	out := c.path("win-extra.openness")
	r := c.run(nil, "collect", "--output", out, "--modules", "security_configuration,applications",
		"--registry-values", b64json(reg), "--file-probes", "@"+probeFile)
	doc, err := c.load(out)
	if !c.check("collect/registry-values+file-probes", r.code == 0 && err == nil, "%s load=%v", r, err) {
		return
	}

	build, _ := powershell(`(Get-CimInstance Win32_OperatingSystem).BuildNumber`)
	wantBuild := strings.TrimSpace(string(build))
	var entry map[string]any
	if sc := asMap(doc.SecurityConfig); sc != nil {
		if list, ok := sc["registry"].([]any); ok {
			for _, it := range list {
				e := asMap(it)
				if strings.EqualFold(str(e, "name"), "CurrentBuild") && strings.Contains(strings.ToLower(str(e, "key")), `windows nt\currentversion`) {
					entry = e
				}
			}
		}
	}
	c.check("collect/registry-values-result", entry != nil && str(entry, "value") == wantBuild && str(entry, "present") == "true",
		"entry=%v want value=%s", entry, wantBuild)

	var checks []any
	for _, v := range values(doc.Applications) {
		if fc, ok := v["file_checks"].([]any); ok && len(fc) > 0 {
			checks = append(checks, fc...)
		}
	}
	ok := false
	for _, it := range checks {
		fc := asMap(it)
		if str(fc, "probe_id") == "hostcheck-git" && str(fc, "exists") == "true" && str(fc, "file_version") != "" {
			ok = true
		}
	}
	c.check("collect/file-probes-result", ok, "file_checks=%v", checks)
}
