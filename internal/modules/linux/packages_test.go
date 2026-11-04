package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s4e-io/openness-collector/internal/schema"
)

func TestDPKGStatusInstalled(t *testing.T) {
	cases := map[string]bool{
		"install ok installed":      true,
		"install ok config-files":   false,
		"deinstall ok config-files": false,
		"purge ok not-installed":    false,
		"":                          false,
		"install":                   false,
	}
	for in, want := range cases {
		if got := dpkgStatusInstalled(in); got != want {
			t.Fatalf("%q: got %v want %v", in, got, want)
		}
	}
}

func TestAppendDPKGStatusParsesInstalledPackages(t *testing.T) {
	const sample = `Package: libc6
Status: install ok installed
Priority: required
Architecture: i386
Version: 2.7-10ubuntu8
Source: eglibc

Package: apache2
Status: install ok installed
Architecture: i386
Version: 2.2.8-1ubuntu0.13

Package: leftover
Status: deinstall ok config-files
Architecture: i386
Version: 1.0-1

Package: ghost
Status: install ok not-installed
Architecture: all
Version: 0
`
	res := &schema.ModuleResult{}
	n, err := appendDPKGStatus(res, "packages", strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("installed count=%d want 2 (got evidence=%d)", n, len(res.Evidence))
	}
	names := map[string]bool{}
	for _, e := range res.Evidence {
		v := e.Value.(map[string]any)
		names[v["name"].(string)] = true
		if v["package_manager"] != "dpkg" {
			t.Fatalf("pm=%v", v["package_manager"])
		}
		raw := e.RawValue.(map[string]string)
		if raw["collection_source"] != "dpkg-status" {
			t.Fatalf("collection_source=%q", raw["collection_source"])
		}
	}
	if !names["libc6"] || !names["apache2"] || names["leftover"] || names["ghost"] {
		t.Fatalf("names=%v", names)
	}
	// Source mapping for libc6
	for _, e := range res.Evidence {
		v := e.Value.(map[string]any)
		if v["name"] == "libc6" {
			if v["source_package"] != "eglibc" {
				t.Fatalf("libc6 source_package=%v", v["source_package"])
			}
			if v["architecture"] != "i386" {
				t.Fatalf("arch=%v", v["architecture"])
			}
		}
	}
}

func TestCollectDPKGFallsBackToStatusFile(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	body := `Package: hello
Status: install ok installed
Architecture: amd64
Version: 2.10-2

`
	if err := os.WriteFile(status, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	old := dpkgStatusPath
	dpkgStatusPath = status
	t.Cleanup(func() { dpkgStatusPath = old })

	// Hide real dpkg-query so Command fails and status fallback runs.
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", dir)
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })

	res := &schema.ModuleResult{}
	collectDPKG(context.Background(), res, "packages")
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence=%d errors=%v", len(res.Evidence), res.Errors)
	}
	v := res.Evidence[0].Value.(map[string]any)
	if v["name"] != "hello" || v["raw_version_string"] != "2.10-2" {
		t.Fatalf("%v", v)
	}
	foundPartial := false
	for _, e := range res.Errors {
		if e.Code == "partial" && strings.Contains(e.Message, "status fallback") {
			foundPartial = true
		}
	}
	if !foundPartial {
		t.Fatalf("expected partial fallback note, got %#v", res.Errors)
	}
}
