package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMapLSBReleaseMetasploitableStyle(t *testing.T) {
	got := mapLSBRelease(map[string]string{
		"DISTRIB_ID":          "Ubuntu",
		"DISTRIB_RELEASE":     "8.04",
		"DISTRIB_CODENAME":    "hardy",
		"DISTRIB_DESCRIPTION": "Ubuntu 8.04.4 LTS",
	})
	if got["ID"] != "ubuntu" {
		t.Fatalf("ID=%q", got["ID"])
	}
	if got["VERSION_ID"] != "8.04" {
		t.Fatalf("VERSION_ID=%q", got["VERSION_ID"])
	}
	if got["VERSION_CODENAME"] != "hardy" {
		t.Fatalf("VERSION_CODENAME=%q", got["VERSION_CODENAME"])
	}
	if got["PRETTY_NAME"] != "Ubuntu 8.04.4 LTS" {
		t.Fatalf("PRETTY_NAME=%q", got["PRETTY_NAME"])
	}
	if got["NAME"] != "Ubuntu" {
		t.Fatalf("NAME=%q", got["NAME"])
	}
}

func TestMapDebianVersion(t *testing.T) {
	got := mapDebianVersion("5.0")
	if got["ID"] != "debian" || got["VERSION_ID"] != "5.0" {
		t.Fatalf("%v", got)
	}
	got = mapDebianVersion("lenny/sid")
	if got["VERSION_ID"] != "lenny" {
		t.Fatalf("VERSION_ID=%q", got["VERSION_ID"])
	}
}

func TestLoadDistroIdentityFallsBackToLSB(t *testing.T) {
	dir := t.TempDir()
	missingOS := filepath.Join(dir, "missing-os-release")
	lsb := filepath.Join(dir, "lsb-release")
	if err := os.WriteFile(lsb, []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=8.04
DISTRIB_CODENAME=hardy
DISTRIB_DESCRIPTION="Ubuntu 8.04.4 LTS"
`), 0o644); err != nil {
		t.Fatal(err)
	}

	oldOS, oldLSB, oldDeb := osReleasePaths, lsbReleasePath, debianVersionPath
	osReleasePaths = []string{missingOS}
	lsbReleasePath = lsb
	debianVersionPath = filepath.Join(dir, "missing-debian-version")
	t.Cleanup(func() {
		osReleasePaths, lsbReleasePath, debianVersionPath = oldOS, oldLSB, oldDeb
	})

	raw, source, err := loadDistroIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if source != lsb {
		t.Fatalf("source=%q", source)
	}
	if raw["ID"] != "ubuntu" || raw["VERSION_ID"] != "8.04" {
		t.Fatalf("%v", raw)
	}
}

func TestLoadDistroIdentityPrefersOsRelease(t *testing.T) {
	dir := t.TempDir()
	osRel := filepath.Join(dir, "os-release")
	lsb := filepath.Join(dir, "lsb-release")
	if err := os.WriteFile(osRel, []byte(`NAME="Ubuntu"
ID=ubuntu
VERSION_ID="20.04"
VERSION="20.04.6 LTS (Focal Fossa)"
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_CODENAME=focal
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lsb, []byte("DISTRIB_ID=ShouldNotWin\nDISTRIB_RELEASE=1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldOS, oldLSB := osReleasePaths, lsbReleasePath
	osReleasePaths = []string{osRel}
	lsbReleasePath = lsb
	t.Cleanup(func() {
		osReleasePaths, lsbReleasePath = oldOS, oldLSB
	})

	raw, source, err := loadDistroIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if source != osRel {
		t.Fatalf("source=%q", source)
	}
	if raw["ID"] != "ubuntu" || raw["VERSION_ID"] != "20.04" || raw["VERSION_CODENAME"] != "focal" {
		t.Fatalf("%v", raw)
	}
}

func TestOSInventoryRunUsesLSBFallback(t *testing.T) {
	dir := t.TempDir()
	lsb := filepath.Join(dir, "lsb-release")
	if err := os.WriteFile(lsb, []byte(`DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=8.04
DISTRIB_CODENAME=hardy
DISTRIB_DESCRIPTION="Ubuntu 8.04.4 LTS"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	oldOS, oldLSB, oldDeb := osReleasePaths, lsbReleasePath, debianVersionPath
	osReleasePaths = []string{filepath.Join(dir, "no-os")}
	lsbReleasePath = lsb
	debianVersionPath = filepath.Join(dir, "no-deb")
	t.Cleanup(func() {
		osReleasePaths, lsbReleasePath, debianVersionPath = oldOS, oldLSB, oldDeb
	})

	res := (&OSInventory{}).Run(context.Background())
	if res.Status != "success" {
		t.Fatalf("status=%s errors=%v", res.Status, res.Errors)
	}
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence=%d", len(res.Evidence))
	}
	v := res.Evidence[0].Value.(map[string]any)
	if v["distribution_id"] != "ubuntu" || v["version_id"] != "8.04" {
		t.Fatalf("%v", v)
	}
	raw := res.Evidence[0].RawValue.(map[string]string)
	if raw["source_file"] != lsb {
		t.Fatalf("source_file=%q", raw["source_file"])
	}
}

func TestLoadDistroIdentityFallsBackToDebianVersion(t *testing.T) {
	dir := t.TempDir()
	deb := filepath.Join(dir, "debian_version")
	if err := os.WriteFile(deb, []byte("5.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldOS, oldLSB, oldDeb := osReleasePaths, lsbReleasePath, debianVersionPath
	osReleasePaths = []string{filepath.Join(dir, "no-os")}
	lsbReleasePath = filepath.Join(dir, "no-lsb")
	debianVersionPath = deb
	t.Cleanup(func() {
		osReleasePaths, lsbReleasePath, debianVersionPath = oldOS, oldLSB, oldDeb
	})

	raw, source, err := loadDistroIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if source != deb {
		t.Fatalf("source=%q", source)
	}
	if raw["ID"] != "debian" || raw["VERSION_ID"] != "5.0" {
		t.Fatalf("%v", raw)
	}
}

func TestReadRebootRequired(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "reboot-required")
	pkgs := filepath.Join(dir, "reboot-required.pkgs")
	deb := filepath.Join(dir, "debian_version")
	if err := os.WriteFile(deb, []byte("12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldM, oldP, oldD := rebootRequiredPath, rebootRequiredPkgsPath, debianVersionPath
	rebootRequiredPath, rebootRequiredPkgsPath, debianVersionPath = marker, pkgs, deb
	t.Cleanup(func() {
		rebootRequiredPath, rebootRequiredPkgsPath, debianVersionPath = oldM, oldP, oldD
	})

	ok, list := readRebootRequired()
	if ok != false || list != nil {
		t.Fatalf("absent: ok=%v list=%v", ok, list)
	}

	if err := os.WriteFile(marker, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, list = readRebootRequired()
	if ok != true || list != nil {
		t.Fatalf("marker only: ok=%v list=%v", ok, list)
	}

	if err := os.WriteFile(pkgs, []byte("linux-image-5.15.0-25-generic\nlibc6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, list = readRebootRequired()
	if ok != true {
		t.Fatal("expected reboot required")
	}
	arr, _ := list.([]string)
	if len(arr) != 2 || arr[0] != "linux-image-5.15.0-25-generic" {
		t.Fatalf("%#v", list)
	}

	// Non-Debian: always null, even if a marker file exists.
	rebootRequiredPath = marker
	debianVersionPath = filepath.Join(dir, "no-debian-version")
	ok, list = readRebootRequired()
	if ok != nil || list != nil {
		t.Fatalf("non-debian: ok=%v list=%v", ok, list)
	}
}
