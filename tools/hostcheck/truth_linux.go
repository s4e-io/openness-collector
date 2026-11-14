//go:build linux

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/s4e-io/openness-collector/internal/schema"
)

var expectedModules = []string{
	"os_inventory", "hardware_inventory", "packages", "kernel_inventory", "services",
	"processes", "listening_ports", "evidence_chain", "loaded_libraries", "containers",
	"language_deps", "security_configuration", "users", "network_inventory", "software_inventory",
}

// Packages whose exact version is reported by name, when installed.
var knownPackages = []string{"bash", "coreutils", "coreutils-single", "base-files", "libc6", "glibc", "busybox", "musl", "openssl", "libssl3", "zlib", "zlib1g", "tar", "sed"}

func (c *checker) platformExtras() {}

func osRelease() map[string]string {
	out := map[string]string{}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(k, "#") {
				continue
			}
			out[k] = strings.Trim(v, `"'`)
		}
		_ = f.Close()
		return out
	}
	return out
}

func utsString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

func (c *checker) hostTruth(doc *schema.Document) {
	osv := asMap(doc.OperatingSystem)
	if !c.check("truth/os-inventory-present", osv != nil, "operating_system object") {
		return
	}
	rel := osRelease()
	var bad []string
	for _, p := range [][2]string{{"ID", "distribution_id"}, {"VERSION_ID", "version_id"}, {"VERSION_CODENAME", "version_codename"}, {"PRETTY_NAME", "pretty_name"}} {
		if got, want := str(osv, p[1]), rel[p[0]]; got != want {
			bad = append(bad, fmt.Sprintf("%s=%q os-release %s=%q", p[1], got, p[0], want))
		}
	}
	c.check("truth/os-release", len(bad) == 0, "id=%s version_id=%s codename=%s %v", rel["ID"], rel["VERSION_ID"], rel["VERSION_CODENAME"], bad)

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		c.check("truth/uname", false, "%v", err)
		return
	}
	release, node, machine := utsString(uts.Release[:]), utsString(uts.Nodename[:]), utsString(uts.Machine[:])
	c.check("truth/kernel", str(osv, "kernel_version") == release, "kernel_version=%q uname -r=%q", str(osv, "kernel_version"), release)
	c.check("truth/hostname", doc.Asset.Hostname == node && str(osv, "hostname") == node,
		"asset=%q os=%q uname -n=%q", doc.Asset.Hostname, str(osv, "hostname"), node)
	c.check("truth/architecture", doc.Asset.Architecture == normArch(machine) && str(osv, "architecture") == normArch(machine),
		"asset=%q os=%q uname -m=%q", doc.Asset.Architecture, str(osv, "architecture"), machine)
	if b, err := os.ReadFile("/etc/machine-id"); err == nil && strings.TrimSpace(string(b)) != "" {
		mid := strings.TrimSpace(string(b))
		c.check("truth/machine-id", doc.Asset.MachineID == mid, "asset=%q /etc/machine-id=%q", doc.Asset.MachineID, mid)
	}

	c.checkPackages(doc)
	c.checkListener(doc)
	c.checkUser(doc)
}

// hostPackages reads the package database with the distro's own tool.
// The result is keyed by manager, then name|arch|version; values are the raw version string.
func hostPackages() (map[string]map[string]string, []string) {
	out := map[string]map[string]string{}
	var errs []string
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		b, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n").Output()
		if err != nil {
			errs = append(errs, "dpkg-query: "+err.Error())
		}
		m := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) == 3 {
				m[f[0]+"|"+f[2]+"|"+f[1]] = f[1]
			}
		}
		out["dpkg"] = m
	}
	if _, err := exec.LookPath("rpm"); err == nil && rpmDBPresent() {
		b, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{ARCH}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\n").Output()
		if err != nil {
			errs = append(errs, "rpm: "+err.Error())
		}
		m := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) != 5 {
				continue
			}
			v := f[3] + "-" + f[4]
			if f[2] != "(none)" && f[2] != "" {
				v = f[2] + ":" + v
			}
			m[f[0]+"|"+f[1]+"|"+v] = v
		}
		out["rpm"] = m
	}
	if _, err := os.Stat("/lib/apk/db/installed"); err == nil {
		if _, err := exec.LookPath("apk"); err == nil {
			// "busybox-1.36.1-r29 aarch64 {busybox} (GPL-2.0-only) [installed]"
			b, err := exec.Command("apk", "list", "--installed").Output()
			if err != nil {
				errs = append(errs, "apk: "+err.Error())
			}
			m := map[string]string{}
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				f := strings.Fields(line)
				if len(f) < 2 {
					continue
				}
				parts := strings.Split(f[0], "-")
				if len(parts) < 3 {
					continue
				}
				name := strings.Join(parts[:len(parts)-2], "-")
				ver := parts[len(parts)-2] + "-" + parts[len(parts)-1]
				m[name+"|"+f[1]+"|"+ver] = ver
			}
			out["apk"] = m
		} else {
			errs = append(errs, "apk db present but apk tool missing")
		}
	}
	return out, errs
}

// rpmDBPresent mirrors the collector: rpm on a dpkg host often has no system database.
func rpmDBPresent() bool {
	for _, p := range []string{
		"/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/var/lib/rpm/Packages.db",
		"/usr/lib/sysimage/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/Packages", "/usr/lib/sysimage/rpm/Packages.db",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func (c *checker) checkPackages(doc *schema.Document) {
	host, errs := hostPackages()
	if !c.check("truth/package-db", len(host) > 0 && len(errs) == 0, "managers=%d errors=%v", len(host), errs) {
		return
	}
	got := map[string]map[string]string{}
	for _, v := range values(doc.Packages) {
		mgr := str(v, "package_manager")
		if got[mgr] == nil {
			got[mgr] = map[string]string{}
		}
		ver := str(v, "raw_version_string")
		got[mgr][str(v, "name")+"|"+str(v, "architecture")+"|"+ver] = ver
	}
	for mgr, want := range host {
		have := got[mgr]
		wantKeys, haveKeys := map[string]bool{}, map[string]bool{}
		for k := range want {
			wantKeys[k] = true
		}
		for k := range have {
			haveKeys[k] = true
		}
		// name|arch|version on both sides: a wrong version shows up as missing + extra.
		missing, extra := setDiff(wantKeys, haveKeys), setDiff(haveKeys, wantKeys)
		c.check("truth/packages/"+mgr, len(want) == len(have) && len(missing) == 0 && len(extra) == 0,
			"collector=%d host=%d missing=[%s] extra=[%s]", len(have), len(want), sample(missing, 5), sample(extra, 5))
		// A manager whose database holds no packages (an empty rpm database on a dpkg
		// runner) has nothing to name; the count check above already covers it.
		if len(want) == 0 {
			continue
		}
		var named []string
		bad := 0
		for _, name := range knownPackages {
			for k, ver := range want {
				if strings.HasPrefix(k, name+"|") {
					ok := haveKeys[k]
					named = append(named, fmt.Sprintf("%s %s ok=%v", strings.SplitN(k, "|", 3)[0], ver, ok))
					if !ok {
						bad++
					}
				}
			}
		}
		sort.Strings(named)
		c.check("truth/known-packages/"+mgr, len(named) >= 2 && bad == 0, "%s", strings.Join(named, "; "))
	}
	for mgr := range got {
		if _, ok := host[mgr]; !ok {
			c.check("truth/package-manager/"+mgr, false, "collector reported %d %s packages, host has no %s database", len(got[mgr]), mgr, mgr)
		}
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
	pid := num(found, "pid")
	c.check("truth/listening-port-detail", str(found, "local_address") == "127.0.0.1" && pid == os.Getpid(),
		"local_address=%s pid=%d want pid=%d", str(found, "local_address"), pid, os.Getpid())
}

func (c *checker) checkUser(doc *schema.Document) {
	var names []string
	found := false
	for _, v := range values(doc.Users) {
		n := str(v, "username")
		names = append(names, n)
		if n == c.opts.user {
			found = true
		}
	}
	c.check("truth/user", found && c.opts.user != "", "user %q among %d users", c.opts.user, len(names))
}
