package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/schema"
)

// apkFixture mirrors a real Alpine 3.20 installed db: extra keys (C, S, I, T,
// U, L, m, t, c, D, p, r, F, R, a, M, Z), a stanza without o:, trailing
// whitespace and CRLF line endings.
const apkFixture = "C:Q1AbCdEf=\n" +
	"P:musl\n" +
	"V:1.2.5-r0\n" +
	"A:aarch64\n" +
	"S:411568\n" +
	"I:676208\n" +
	"T:the musl c library (libc) implementation\n" +
	"U:https://musl.libc.org/\n" +
	"L:MIT\n" +
	"o:musl\n" +
	"m:Natanael Copa <ncopa@alpinelinux.org>\n" +
	"t:1712653034\n" +
	"c:82e6e4e2b6ea9e7a8e1d6f8b0c3c2a1e9f0d1234\n" +
	"p:so:libc.musl-aarch64.so.1=1\n" +
	"F:lib\n" +
	"R:ld-musl-aarch64.so.1\n" +
	"a:0:0:755\n" +
	"Z:Q1xyz=\n" +
	"\n" +
	"P:libcrypto3   \n" +
	"V:3.3.2-r0\t\n" +
	"A:aarch64\n" +
	"o:openssl\n" +
	"D:so:libc.musl-aarch64.so.1\n" +
	"\n" +
	"P:busybox\r\n" +
	"V:1.36.1-r29\r\n" +
	"A:aarch64\r\n" +
	"o:busybox\r\n" +
	"\r\n" +
	"P:local-tool\n" +
	"V:0.1\n" +
	"A:noarch\n" +
	"\n" +
	"\n" +
	"V:9.9-r9\n" +
	"A:aarch64\n"

func TestParseAPKDB(t *testing.T) {
	pkgs, err := parseAPKDB(strings.NewReader(apkFixture), 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []apkPackage{
		{Name: "musl", Version: "1.2.5-r0", Arch: "aarch64", Origin: "musl"},
		{Name: "libcrypto3", Version: "3.3.2-r0", Arch: "aarch64", Origin: "openssl"},
		{Name: "busybox", Version: "1.36.1-r29", Arch: "aarch64", Origin: "busybox"},
		{Name: "local-tool", Version: "0.1", Arch: "noarch"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages %#v", len(pkgs), pkgs)
	}
	for i := range want {
		if pkgs[i] != want[i] {
			t.Fatalf("pkg %d: got %#v want %#v", i, pkgs[i], want[i])
		}
	}
}

func TestParseAPKDBLimit(t *testing.T) {
	pkgs, err := parseAPKDB(strings.NewReader(apkFixture), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[1].Name != "libcrypto3" {
		t.Fatalf("%#v", pkgs)
	}
}

func TestSplitAPKVersion(t *testing.T) {
	cases := map[string][2]string{
		"1.2.5-r0":           {"1.2.5", "r0"},
		"1.36.1-r29":         {"1.36.1", "r29"},
		"0.1":                {"0.1", ""},
		"2.0_rc1-r3":         {"2.0_rc1", "r3"},
		"1.0-rc":             {"1.0-rc", ""},
		"":                   {"", ""},
		"20240226-r0":        {"20240226", "r0"},
		"3.3.2-r0-something": {"3.3.2-r0-something", ""},
	}
	for in, w := range cases {
		v, r := splitAPKVersion(in)
		if v != w[0] || r != w[1] {
			t.Fatalf("%q: got (%q,%q) want (%q,%q)", in, v, r, w[0], w[1])
		}
	}
}

func TestCollectAPKHostRecords(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "installed")
	if err := os.WriteFile(db, []byte(apkFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	res := &schema.ModuleResult{}
	collectAPK(res, "packages", db)
	if len(res.Errors) != 0 {
		t.Fatalf("errors=%v", res.Errors)
	}
	if len(res.Evidence) != 4 {
		t.Fatalf("evidence=%d", len(res.Evidence))
	}
	byName := map[string]map[string]any{}
	for _, e := range res.Evidence {
		v := e.Value.(map[string]any)
		byName[v["name"].(string)] = v
		if v["package_manager"] != "apk" || v["package_status"] != "installed" {
			t.Fatalf("%v", v)
		}
		if _, ok := v["packages_scope"]; ok {
			t.Fatalf("host record must not carry packages_scope: %v", v)
		}
		if e.RawValue.(map[string]string)["collection_source"] != "apk-installed-db" {
			t.Fatalf("raw=%v", e.RawValue)
		}
	}
	lc := byName["libcrypto3"]
	if lc["source_package"] != "openssl" || lc["raw_version_string"] != "3.3.2-r0" ||
		lc["version"] != "3.3.2" || lc["release"] != "r0" || lc["architecture"] != "aarch64" {
		t.Fatalf("libcrypto3=%v", lc)
	}
	if lc["entity_id"] != "pkg:apk:libcrypto3:aarch64:3.3.2-r0" {
		t.Fatalf("entity_id=%v", lc["entity_id"])
	}
	rels := lc["relationships"].([]map[string]any)
	if len(rels) != 1 || rels[0]["target_entity_id"] != "srcpkg:apk:openssl" || rels[0]["confidence"] != "direct" {
		t.Fatalf("rels=%v", rels)
	}
	lt := byName["local-tool"]
	if lt["source_package"] != "local-tool" || lt["release"] != nil {
		t.Fatalf("local-tool=%v", lt)
	}
	rels = lt["relationships"].([]map[string]any)
	if rels[0]["confidence"] != "inferred" || rels[0]["evidence_source"] != "binary_name_fallback" {
		t.Fatalf("rels=%v", rels)
	}
	if lt["package_database_path"] != db {
		t.Fatalf("db path=%v", lt["package_database_path"])
	}
}

func TestPackagesRunUsesAPKWhenNoDpkgOrRpm(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "installed")
	if err := os.WriteFile(db, []byte(apkFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	old := apkInstalledPath
	apkInstalledPath = db
	t.Cleanup(func() { apkInstalledPath = old })
	// Hide dpkg-query and rpm.
	t.Setenv("PATH", dir)

	res := (&Packages{}).Run(t.Context())
	if res.Status != "success" {
		t.Fatalf("status=%q errors=%v", res.Status, res.Errors)
	}
	if len(res.Evidence) != 4 {
		t.Fatalf("evidence=%d", len(res.Evidence))
	}
}

func TestPackagesRunUnavailableWithoutAnyDB(t *testing.T) {
	dir := t.TempDir()
	old := apkInstalledPath
	apkInstalledPath = filepath.Join(dir, "missing")
	t.Cleanup(func() { apkInstalledPath = old })
	t.Setenv("PATH", dir)

	res := (&Packages{}).Run(t.Context())
	if res.Status != "unavailable" || len(res.Errors) != 1 || res.Errors[0].Message != "no supported package manager found" {
		t.Fatalf("status=%q errors=%v", res.Status, res.Errors)
	}
}
