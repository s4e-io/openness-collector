package swinv

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCatalogLoadsAndIsWellFormed(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) < 10 {
		t.Fatalf("catalog too small: %d", len(cat))
	}
	for _, p := range cat {
		if p.Vendor == "" || p.Product == "" {
			t.Errorf("%s: vendor/product required", p.ProductKey)
		}
		for _, r := range p.Readers {
			if (r.Type == "file_regex" || r.Type == "dir_names" || r.Type == "zip_entry_regex") && r.re == nil {
				t.Errorf("%s: reader %s not compiled", p.ProductKey, r.Type)
			}
		}
		for _, pl := range p.Platforms {
			if pl != "linux" && pl != "windows" {
				t.Errorf("%s: unknown platform %s", p.ProductKey, pl)
			}
		}
	}
}

func TestFileRegexFirstAcrossChunkBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	// Place the marker so it straddles the 1 MiB chunk boundary.
	pad := strings.Repeat("x", scanChunk-6)
	if err := os.WriteFile(path, []byte(pad+"nginx/1.27.5\x00tail"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Reader{Type: "file_regex", Path: "bin", Pattern: `nginx/([0-9]+\.[0-9]+\.[0-9]+)`}
	if err := compileReader(&r); err != nil {
		t.Fatal(err)
	}
	v, ok := fileRegexFirst(path, &r)
	if !ok || v != "1.27.5" {
		t.Fatalf("got %q ok=%v", v, ok)
	}
}

func TestFileRegexRespectsMaxBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	if err := os.WriteFile(path, []byte(strings.Repeat("y", 4096)+"OpenSSL 3.0.2 15 Mar 2022"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := Reader{Type: "file_regex", Path: "bin", Pattern: `OpenSSL ([0-9.]+) `, MaxBytes: 1024}
	if err := compileReader(&r); err != nil {
		t.Fatal(err)
	}
	if _, ok := fileRegexFirst(path, &r); ok {
		t.Fatal("must not read past max_bytes")
	}
}

func TestDirNamesAndPatchList(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"35320081", "36233263", "README", "12_backup"} {
		if err := os.Mkdir(filepath.Join(dir, "oneoffs", n), 0o755); err != nil && !os.IsExist(err) {
			os.MkdirAll(filepath.Join(dir, "oneoffs", n), 0o755)
		}
	}
	r := Reader{Type: "dir_names", Path: "oneoffs/*", Pattern: `^([0-9]{6,})$`}
	if err := compileReader(&r); err != nil {
		t.Fatal(err)
	}
	got := dirNames(filepath.Join(dir, "oneoffs", "*"), &r)
	if len(got) != 2 || got[0] != "35320081" || got[1] != "36233263" {
		t.Fatalf("%v", got)
	}
}

func TestZipEntryRegex(t *testing.T) {
	dir := t.TempDir()
	jar := filepath.Join(dir, "catalina.jar")
	f, err := os.Create(jar)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("org/apache/catalina/util/ServerInfo.properties")
	w.Write([]byte("server.info=Apache Tomcat/10.1.61\nserver.number=10.1.61.0\n"))
	zw.Close()
	f.Close()
	r := Reader{Type: "zip_entry_regex", Path: "lib/catalina.jar", Value: "org/apache/catalina/util/ServerInfo.properties", Pattern: `server\.number=([0-9]+\.[0-9]+\.[0-9]+)`}
	if err := compileReader(&r); err != nil {
		t.Fatal(err)
	}
	v, ok := zipEntryRegexFirst(jar, r.Value, &r)
	if !ok || v != "10.1.61" {
		t.Fatalf("got %q ok=%v", v, ok)
	}
}

// TestDetectOnFakeRoot builds a fake filesystem root with a Java release file,
// an nginx binary and an Oracle home, then checks instances and gaps.
func TestDetectOnFakeRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake root uses Unix catalog paths")
	}
	root := t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(root, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk("usr/lib/jvm/java-17-openjdk-arm64/release", "IMPLEMENTOR=\"Ubuntu\"\nJAVA_VERSION=\"17.0.9\"\n")
	mk("usr/sbin/nginx", "\x00\x00nginx/1.24.0\x00")
	mk("u01/app/oracle/product/19.0.0/dbhome_1/inventory/ContentsXML/comps.xml", `<COMP NAME="oracle.server" VER="19.0.0.0.0" BUILD_NUMBER="0" REP_VER="0.0.0.0.0" RELEASE="Production"/>`)
	os.MkdirAll(filepath.Join(root, "u01/app/oracle/product/19.0.0/dbhome_1/inventory/oneoffs/36233263"), 0o755)
	os.MkdirAll(filepath.Join(root, "u01/app/oracle/product/19.0.0/dbhome_1/inventory/oneoffs/35320081"), 0o755)
	// A product seen by path but with no readable version.
	mk("usr/sbin/sshd", "no version string here")

	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	procs := []procInfo{{PID: 42, Name: "nginx", Exe: filepath.Join(root, "usr/sbin/nginx")}}
	byKey := map[string]map[string]any{}
	for _, p := range cat {
		for _, in := range detect(p, "host", root, "linux", procs, map[int][]int{80: {42}, 443: {7}, 22: nil}) {
			byKey[p.ProductKey] = in.value()
		}
	}
	java := byKey["java-runtime"]
	if java == nil || java["version"] != "17.0.9" || java["confidence"] != confidenceDirect {
		t.Fatalf("java: %v", java)
	}
	ng := byKey["nginx"]
	if ng == nil || ng["version"] != "1.24.0" || ng["running"] != true {
		t.Fatalf("nginx: %v", ng)
	}
	if ports := ng["signals"].(map[string]any)["ports"].([]int); len(ports) != 1 || ports[0] != 80 {
		t.Fatalf("nginx ports: %v", ports)
	}
	ora := byKey["oracle-database"]
	if ora == nil || ora["version"] != "19.0.0.0.0" {
		t.Fatalf("oracle: %v", ora)
	}
	if ids := ora["patch_ids"].([]string); len(ids) != 2 || ids[0] != "35320081" {
		t.Fatalf("oracle patches: %v", ids)
	}
	if ora["catalog_verified"] != false {
		t.Fatal("oracle entry must be marked unverified")
	}
	ssh := byKey["openssh-server"]
	if ssh == nil || ssh["version"] != nil || ssh["gap"] != "version_unreadable" || ssh["confidence"] != confidencePresence {
		t.Fatalf("sshd: %v", ssh)
	}
	if _, found := byKey["postgresql"]; found {
		t.Fatal("postgresql must not be detected on an empty root")
	}
	// entity_id is stable across runs and does not embed the version.
	if id := java["entity_id"].(string); !strings.HasPrefix(id, "sw:java-runtime:host:") || strings.Contains(id, "17.0.9") {
		t.Fatalf("entity_id %q", id)
	}
}

func TestInstallDirFor(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "opt", "pg", "bin"), 0o755)
	os.WriteFile(filepath.Join(dir, "opt", "pg", "bin", "postgres"), []byte("x"), 0o755)
	if got := installDirFor(filepath.Join(dir, "opt", "pg", "bin", "postgres")); got != filepath.Join(dir, "opt", "pg") {
		t.Fatalf("%s", got)
	}
	if got := installDirFor(filepath.Join(dir, "opt", "pg")); got != filepath.Join(dir, "opt", "pg") {
		t.Fatalf("%s", got)
	}
}

func TestRunProducesSummaryFirst(t *testing.T) {
	res := (&SoftwareInventory{}).Run(context.Background())
	if len(res.Evidence) == 0 {
		t.Fatal("summary expected")
	}
	v := res.Evidence[0].Value.(map[string]any)
	if v["entity_type"] != "software_inventory_summary" || v["catalog_version"] != CatalogVersion {
		t.Fatalf("%v", v)
	}
	if res.Status != "success" && res.Status != "partial" {
		t.Fatalf("status %s errors %v", res.Status, res.Errors)
	}
}

// TestRealBinaries runs the catalog readers against product binaries copied
// out of official images. Set SWINV_VERIFY_DIR to the directory holding them.
func TestRealBinaries(t *testing.T) {
	dir := os.Getenv("SWINV_VERIFY_DIR")
	if dir == "" {
		t.Skip("SWINV_VERIFY_DIR not set")
	}
	cases := []struct{ file, key, want string }{
		{"nginx", "nginx", "1.27.5"},
		{"postgres", "postgresql", "16.15"},
		{"mysqld", "mysql-server", "8.4.13"},
		{"mariadbd", "mariadb-server", "11.8.9"},
		{"httpd", "apache-httpd", "2.4.69"},
		{"redis-server", "redis", "7.4.11"},
		{"libcrypto.so.3", "openssl", "3.3.7"},
		{"sshd", "openssh-server", "9.7p1"},
		{"release", "java-runtime", "17.0.20.1"},
		{"RELEASE-NOTES", "apache-tomcat", "10.1.61"},
	}
	cat, _ := LoadCatalog()
	byKey := map[string]Product{}
	for _, p := range cat {
		byKey[p.ProductKey] = p
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: missing", c.file)
			continue
		}
		p := byKey[c.key]
		var got string
		for _, r := range p.Readers {
			if r.Type != "file_regex" || !r.supports("linux") {
				continue
			}
			if filepath.Base(r.Path) != c.file && !globMatchBase(r.Path, c.file) {
				continue
			}
			if v, ok := fileRegexFirst(path, &r); ok {
				got = v
				break
			}
		}
		if got != c.want {
			t.Errorf("%s (%s): got %q want %q", c.key, c.file, got, c.want)
		}
	}
	// Tomcat jar reader
	if p, ok := byKey["apache-tomcat"]; ok {
		for _, r := range p.Readers {
			if r.Type == "zip_entry_regex" {
				if v, ok := zipEntryRegexFirst(filepath.Join(dir, "catalina.jar"), r.Value, &r); !ok || v != "10.1.61" {
					t.Errorf("catalina.jar: got %q ok=%v", v, ok)
				}
			}
		}
	}
}

func globMatchBase(pattern, name string) bool {
	ok, _ := filepath.Match(filepath.Base(pattern), name)
	return ok
}

// TestOwnedPorts: a port belongs to an instance only through its own pids.
func TestOwnedPorts(t *testing.T) {
	listening := map[int][]int{80: {4}, 443: {100, 101}, 8080: nil}
	if got := ownedPorts([]int{80, 443}, listening, nil); len(got) != 0 {
		t.Fatalf("stopped instance must not inherit ports: %v", got)
	}
	if got := ownedPorts([]int{80, 443}, listening, []procInfo{{PID: 101}}); len(got) != 1 || got[0] != 443 {
		t.Fatalf("only the port owned by the instance's pid: %v", got)
	}
	if got := ownedPorts([]int{8080}, listening, []procInfo{{PID: 100}}); len(got) != 0 {
		t.Fatalf("unknown owner is not attributed: %v", got)
	}
}
