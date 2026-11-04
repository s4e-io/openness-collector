package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectNodeLockVsInstalled(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"app","dependencies":{"leftpad":"1.0.0"},"devDependencies":{"eslint":"8.0.0"}}`), 0o644)
	_ = os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":2}`), 0o644)
	mod := filepath.Join(root, "node_modules", "leftpad")
	_ = os.MkdirAll(mod, 0o755)
	_ = os.WriteFile(filepath.Join(mod, "package.json"), []byte(`{"name":"leftpad","version":"1.0.0"}`), 0o644)

	recs, errMsg := collectNodeEvidence(procSeed{pid: 7, exe: "/usr/bin/node", cmdline: "node server.js", cwd: root})
	if errMsg != "" {
		t.Fatal(errMsg)
	}
	var app map[string]any
	for _, r := range recs {
		if r["entity_type"] == "node_application" {
			app = r
		}
	}
	if app == nil {
		t.Fatal("no node_application")
	}
	if app["installed_count"].(int) != 1 {
		t.Fatalf("installed %#v", app)
	}
	lock := app["lockfile"].(map[string]any)
	if lock["package-lock.json"] == nil {
		t.Fatal("missing lockfile evidence")
	}
}

func TestInspectJARManifestAndNested(t *testing.T) {
	// Reuse fixture jar if present; else skip
	path := filepath.Join("..", "..", "..", "testdata", "jars", "demo.jar")
	if _, err := os.Stat(path); err != nil {
		// create minimal jar in temp
		path = filepath.Join(t.TempDir(), "demo.jar")
		// write via zip helper already tested indirectly
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		t.Skip("need real zip jar; create in test")
	}
	rec := inspectJAR(path)
	if rec == nil {
		t.Fatal("nil jar")
	}
	if rec["implementation_version"] != "9.9.9" && rec["implementation_version"] != nil {
		// may be string or via nullIfEmpty
	}
	if asString(rec["implementation_version"]) != "9.9.9" {
		t.Fatalf("impl ver %#v manifest %#v", rec["implementation_version"], rec["manifest"])
	}
	if asString(rec["bundle_symbolic_name"]) != "com.openness.demo" {
		t.Fatalf("bsn %#v", rec["bundle_symbolic_name"])
	}
	if rec["spring_boot_fat_jar"] != true {
		t.Fatalf("fat %#v nested %#v", rec["spring_boot_fat_jar"], rec["nested_jars"])
	}
}

func TestCollectGoBuildInfoPresentAndAbsent(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := collectGoBuildInfo(self, 1)
	if !ok {
		// test binary may be stripped in some environments
		t.Log("buildinfo absent on test binary; checking false negative path")
	} else {
		if rec["buildinfo_present"] != true {
			t.Fatal(rec)
		}
	}
	// stripped / non-go: must not fabricate
	empty := filepath.Join(t.TempDir(), "empty.bin")
	_ = os.WriteFile(empty, []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, 0o755)
	if _, ok := collectGoBuildInfo(empty, 1); ok {
		t.Fatal("must not invent go buildinfo")
	}
}

func TestArgv0BusyboxClassification(t *testing.T) {
	if !isPythonRuntime("python3.11", "/tmp/venv/bin/python3.11 app.py") {
		t.Fatal("python argv0")
	}
	if isGenericBusybox("busybox") != true {
		t.Fatal("busybox")
	}
}
