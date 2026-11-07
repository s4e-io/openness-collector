package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/s4e-io/openness-collector/internal/schema"
)

// isolatePackageDBs points every host package database path at missing
// files under dir so tests never read the machine's real databases.
func isolatePackageDBs(t *testing.T, dir string) {
	t.Helper()
	oldStatus, oldStatusD, oldAPK, oldRPM, oldLimit := dpkgStatusPath, dpkgStatusDDir, apkInstalledPath, rpmDBPaths, hostPackageLimit
	dpkgStatusPath = filepath.Join(dir, "missing-status")
	dpkgStatusDDir = filepath.Join(dir, "missing-status.d")
	apkInstalledPath = filepath.Join(dir, "missing-apk")
	rpmDBPaths = []string{filepath.Join(dir, "missing-rpmdb")}
	t.Cleanup(func() {
		dpkgStatusPath, dpkgStatusDDir, apkInstalledPath, rpmDBPaths, hostPackageLimit = oldStatus, oldStatusD, oldAPK, oldRPM, oldLimit
	})
}

// skipWithoutShellFakes skips tests whose fake dpkg-query, rpm or docker are
// shell scripts; Windows cannot run them.
func skipWithoutShellFakes(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake package tools are shell scripts; not runnable on Windows")
	}
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// Distroless status.d stanzas carry no Status field.
const statusDLibc = `Package: libc6
Version: 2.36-9+deb12u7
Architecture: arm64
Source: glibc
Description: GNU C Library
 multi-line description
`

const statusDOpenssl = `Package: libssl3
Version: 3.0.14-1~deb12u2
Architecture: arm64
Source: openssl
`

func makeStatusD(t *testing.T, dir string) {
	writeFile(t, filepath.Join(dir, "libc6"), statusDLibc, 0o644)
	writeFile(t, filepath.Join(dir, "libc6.md5sums"), "d41d8cd98f00b204e9800998ecf8427e  lib/x\n", 0o644)
	writeFile(t, filepath.Join(dir, "libssl3"), statusDOpenssl, 0o644)
	writeFile(t, filepath.Join(dir, "libssl3.md5sums"), "d41d8cd98f00b204e9800998ecf8427e  lib/y\n", 0o644)
}

func TestPackagesRunReadsDistrolessStatusD(t *testing.T) {
	dir := t.TempDir()
	isolatePackageDBs(t, dir)
	dpkgStatusDDir = filepath.Join(dir, "status.d")
	makeStatusD(t, dpkgStatusDDir)
	t.Setenv("PATH", dir) // no dpkg-query, no rpm

	res := (&Packages{}).Run(t.Context())
	if res.Status != "success" || len(res.Evidence) != 2 {
		t.Fatalf("status=%s evidence=%d errors=%v", res.Status, len(res.Evidence), res.Errors)
	}
	v := res.Evidence[0].Value.(map[string]any)
	if v["name"] != "libc6" || v["source_package"] != "glibc" || v["raw_version_string"] != "2.36-9+deb12u7" ||
		v["package_database_path"] != dpkgStatusDDir || v["package_status"] != "install ok installed" {
		t.Fatalf("%v", v)
	}
	if res.Evidence[0].RawValue.(map[string]string)["collection_source"] != "dpkg-status.d" {
		t.Fatalf("raw=%v", res.Evidence[0].RawValue)
	}
}

func TestPackagesRunReadsStatusFileWithoutDpkgQuery(t *testing.T) {
	dir := t.TempDir()
	isolatePackageDBs(t, dir)
	dpkgStatusPath = filepath.Join(dir, "status")
	writeFile(t, dpkgStatusPath, "Package: hello\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.10-2\n", 0o644)
	t.Setenv("PATH", dir)
	res := (&Packages{}).Run(t.Context())
	if res.Status != "success" || len(res.Evidence) != 1 {
		t.Fatalf("status=%s evidence=%d errors=%v", res.Status, len(res.Evidence), res.Errors)
	}
}

func TestPackagesRunZeroPackagesIsExplicit(t *testing.T) {
	dir := t.TempDir()
	isolatePackageDBs(t, dir)
	dpkgStatusPath = filepath.Join(dir, "status")
	writeFile(t, dpkgStatusPath, "", 0o644)
	t.Setenv("PATH", dir)
	res := (&Packages{}).Run(t.Context())
	if res.Status != "unavailable" {
		t.Fatalf("status=%s", res.Status)
	}
	last := res.Errors[len(res.Errors)-1]
	if last.Code != "no_packages" || !strings.Contains(last.Message, "no installed packages") {
		t.Fatalf("errors=%v", res.Errors)
	}
}

func bigStatus(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "Package: p%05d\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.%d\nDescription: x\n long\n\n", i, i)
	}
	return b.String()
}

func TestHostPackageLimitTruncates(t *testing.T) {
	dir := t.TempDir()
	isolatePackageDBs(t, dir)
	hostPackageLimit = 50
	dpkgStatusPath = filepath.Join(dir, "status")
	writeFile(t, dpkgStatusPath, bigStatus(200), 0o644)
	t.Setenv("PATH", dir)
	res := (&Packages{}).Run(t.Context())
	if len(res.Evidence) != 50 || !res.Truncated || res.Status != "partial" {
		t.Fatalf("evidence=%d truncated=%v status=%s", len(res.Evidence), res.Truncated, res.Status)
	}
	n := 0
	for _, e := range res.Errors {
		if e.Code == "package_limit_truncated" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want one package_limit_truncated error, got %v", res.Errors)
	}
}

func TestHostPackageLimitExactIsNotTruncated(t *testing.T) {
	dir := t.TempDir()
	isolatePackageDBs(t, dir)
	hostPackageLimit = 50
	res := &schema.ModuleResult{}
	if _, err := appendDPKGStatus(res, "packages", strings.NewReader(bigStatus(50))); err != nil {
		t.Fatal(err)
	}
	if len(res.Evidence) != 50 || res.Truncated {
		t.Fatalf("evidence=%d truncated=%v", len(res.Evidence), res.Truncated)
	}
}

// A dpkg-query that prints forever: streaming stops at the limit and the
// process is killed instead of being read to the end.
func TestCollectDPKGStopsEndlessOutput(t *testing.T) {
	skipWithoutShellFakes(t)
	dir := t.TempDir()
	isolatePackageDBs(t, dir)
	hostPackageLimit = 100
	writeFile(t, filepath.Join(dir, "dpkg-query"), "#!/bin/sh\ni=0\nwhile :; do printf 'p%d\\t1.0\\tamd64\\tinstall ok installed\\t\\n' $i; i=$((i+1)); done\n", 0o755)
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	res := &schema.ModuleResult{}
	collectDPKG(ctx, res, "packages")
	if ctx.Err() != nil {
		t.Fatal("collectDPKG ran until the deadline")
	}
	if len(res.Evidence) != 100 || !res.Truncated {
		t.Fatalf("evidence=%d truncated=%v errors=%v", len(res.Evidence), res.Truncated, res.Errors)
	}
}

func TestContainerPackagesStatusDAndLimit(t *testing.T) {
	root := t.TempDir()
	makeStatusD(t, filepath.Join(root, "var/lib/dpkg/status.d"))
	pkgs, truncated, perr := readContainerPackages(t.Context(), root, 100)
	if perr != "" || truncated || len(pkgs) != 2 || pkgs[0]["name"] != "libc6" {
		t.Fatalf("pkgs=%v truncated=%v perr=%q", pkgs, truncated, perr)
	}
	pkgs, truncated, _ = readContainerPackages(t.Context(), root, 1)
	if len(pkgs) != 1 || !truncated {
		t.Fatalf("limit 1: pkgs=%d truncated=%v", len(pkgs), truncated)
	}

	root2 := t.TempDir()
	writeFile(t, filepath.Join(root2, "var/lib/dpkg/status"), bigStatus(30000), 0o644)
	pkgs, truncated, _ = readContainerPackages(t.Context(), root2, maxContainerPackages)
	if len(pkgs) != maxContainerPackages || !truncated {
		t.Fatalf("pkgs=%d truncated=%v", len(pkgs), truncated)
	}
}

// A hanging rpm inside a container rootfs scan must not outlive the context.
func TestContainerRPMHangHonoursContext(t *testing.T) {
	skipWithoutShellFakes(t)
	dir := t.TempDir()
	root := t.TempDir()
	writeFile(t, filepath.Join(dir, "rpm"), "#!/bin/sh\nsleep 300 &\nwait\n", 0o755)
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, perr := readContainerPackages(ctx, root, 100)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("readContainerPackages took %s", d)
	}
	if perr != "rpm_timeout" {
		t.Fatalf("perr=%q", perr)
	}
}

// Fake runtime whose cp hands back a large dpkg status: truncation must
// survive the runtime_cp fallback and be visible on the record.
func TestContainersRuntimeCopyKeepsTruncation(t *testing.T) {
	skipWithoutShellFakes(t)
	dir := t.TempDir()
	statusFile := filepath.Join(dir, "status-big")
	writeFile(t, statusFile, bigStatus(maxContainerPackages+10), 0o644)
	shim := `#!/bin/sh
case "$1" in
ps) echo '{"ID":"c0000000000001","Names":"rfix","Image":"debian:12","State":"running"}';;
inspect) echo '[{"Id":"c0000000000001","Name":"/rfix","Config":{"Image":"debian:12"},"Image":"sha256:aa","GraphDriver":{"Data":{"MergedDir":"/nonexistent/rootfs"}}}]';;
image) echo '[]';;
cp) case "$2" in *dpkg/status) cp ` + statusFile + ` "$3";; *) exit 1;; esac;;
*) exit 1;;
esac
`
	writeFile(t, filepath.Join(dir, "docker"), shim, 0o755)
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	res := (&Containers{}).Run(t.Context())
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence=%d errors=%v", len(res.Evidence), res.Errors)
	}
	v := res.Evidence[0].Value.(map[string]any)
	if v["package_source"] != "runtime_cp" || v["package_count"] != maxContainerPackages ||
		v["packages_truncated"] != true || v["package_limit"] != maxContainerPackages {
		t.Fatalf("record: source=%v count=%v truncated=%v limit=%v", v["package_source"], v["package_count"], v["packages_truncated"], v["package_limit"])
	}
	found := false
	for _, e := range res.Errors {
		if e.Code == "package_limit_truncated" {
			found = true
		}
	}
	if !found || res.Status != "partial" || !res.Truncated {
		t.Fatalf("status=%s truncated=%v errors=%v", res.Status, res.Truncated, res.Errors)
	}
}

// An rpm database that cannot be read is reported with a specific code;
// a rootfs without any package database stays no_package_database.
func TestContainerRPMReadErrors(t *testing.T) {
	withDB := func(t *testing.T) string {
		root := t.TempDir()
		writeFile(t, filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), "x", 0o644)
		return root
	}
	cases := []struct {
		name     string
		rpm      string // fake rpm script; empty means no rpm on PATH
		db       bool
		wantCode string
	}{
		{"exit non-zero with database", "#!/bin/sh\necho broken >&2\nexit 1\n", true, pkgErrReadFailed},
		{"exit non-zero without database", "#!/bin/sh\nexit 1\n", false, "no_package_database"},
		{"rpm missing with database", "", true, pkgErrRPMUnavailable},
		{"rpm missing without database", "", false, "no_package_database"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.rpm != "" {
				writeFile(t, filepath.Join(dir, "rpm"), tc.rpm, 0o755)
			}
			t.Setenv("PATH", dir+":/bin:/usr/bin")
			if _, err := exec.LookPath("rpm"); (err == nil) != (tc.rpm != "") {
				t.Skip("host rpm on /bin or /usr/bin")
			}
			root := t.TempDir()
			if tc.db {
				root = withDB(t)
			}
			pkgs, _, perr := readContainerPackages(t.Context(), root, 100)
			code, _, _ := strings.Cut(perr, ": ")
			if len(pkgs) != 0 || code != tc.wantCode {
				t.Fatalf("pkgs=%d perr=%q", len(pkgs), perr)
			}
			pe := containerPackagesError(perr)
			if (pe != nil) != tc.db || (pe != nil && pe["code"] != tc.wantCode) {
				t.Fatalf("packages_error=%v", pe)
			}
		})
	}
}

// A container whose rpm read times out carries packages_error and the module
// error uses container_packages_unread, not the generic partial code.
func TestContainersRPMTimeoutRecorded(t *testing.T) {
	skipWithoutShellFakes(t)
	dir := t.TempDir()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), "x", 0o644)
	writeFile(t, filepath.Join(root, "etc/os-release"), rocky9OSRelease, 0o644)
	writeFile(t, filepath.Join(dir, "rpm"), "#!/bin/sh\nsleep 300 &\nwait\n", 0o755)
	shim := `#!/bin/sh
case "$1" in
ps) echo '{"ID":"c0000000000001","Names":"rocky","Image":"rockylinux:9","State":"running"}';;
inspect) echo '[{"Id":"c0000000000001","Name":"/rocky","Config":{"Image":"rockylinux:9"},"Image":"sha256:aa","GraphDriver":{"Data":{"MergedDir":"` + root + `"}}}]';;
image) echo '[]';;
*) exit 1;;
esac
`
	writeFile(t, filepath.Join(dir, "docker"), shim, 0o755)
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	res := (&Containers{}).Run(ctx)
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence=%d errors=%v", len(res.Evidence), res.Errors)
	}
	v := res.Evidence[0].Value.(map[string]any)
	pe, _ := v["packages_error"].(map[string]any)
	if pe == nil || pe["code"] != pkgErrRPMTimeout || pe["message"] == "" || v["package_count"] != 0 {
		t.Fatalf("record: packages_error=%v package_count=%v", v["packages_error"], v["package_count"])
	}
	found := false
	for _, e := range res.Errors {
		if e.Code == "container_packages_unread" && e.Message == "c00000000000: rpm_timeout" {
			found = true
		}
		if e.Code == "partial" {
			t.Fatalf("generic partial error: %v", e)
		}
	}
	if !found || res.Status != "partial" {
		t.Fatalf("status=%s errors=%v", res.Status, res.Errors)
	}
}
