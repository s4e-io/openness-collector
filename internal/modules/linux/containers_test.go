package linux

import (
	"strings"
	"testing"
)

func TestParseDpkgStatusContainer(t *testing.T) {
	in := `Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.35-0ubuntu3

Package: bash
Status: deinstall ok config-files
Architecture: amd64
Version: 5.1-6

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.2-0ubuntu1
`
	pkgs, _ := parseDpkgStatus(strings.NewReader(in), nil, maxContainerPackages)
	if len(pkgs) != 2 {
		t.Fatalf("want 2 installed, got %d %#v", len(pkgs), pkgs)
	}
	if pkgs[0]["name"] != "libc6" || pkgs[1]["name"] != "openssl" {
		t.Fatalf("names %#v", pkgs)
	}
	if pkgs[0]["packages_scope"] != "container" {
		t.Fatalf("scope")
	}
}

func TestFirstStringContainerIDKeys(t *testing.T) {
	// docker ps --format '{{json .}}' uses uppercase ID
	row := map[string]any{"ID": "abc123def456", "Names": "openness-test-alpine", "Image": "alpine:3.19"}
	if got := firstString(row, "ID", "Id", "id"); got != "abc123def456" {
		t.Fatalf("got %q", got)
	}
	if firstString(map[string]any{"Id": "x"}, "ID", "Id", "id") != "x" {
		t.Fatal("Id fallback")
	}
}

func TestParseAPKInstalled(t *testing.T) {
	in := `P:musl
V:1.2.3-r4
A:x86_64

P:busybox
V:1.35.0-r29
A:x86_64
`
	pkgs, _ := parseAPKInstalled(strings.NewReader(in), nil, maxContainerPackages)
	if len(pkgs) != 2 {
		t.Fatalf("got %d", len(pkgs))
	}
	if pkgs[0]["name"] != "musl" || pkgs[0]["raw_version_string"] != "1.2.3-r4" {
		t.Fatalf("%#v", pkgs[0])
	}
}

func TestParseAPKInstalledSharesHostParser(t *testing.T) {
	pkgs, _ := parseAPKInstalled(strings.NewReader(apkFixture), nil, maxContainerPackages)
	if len(pkgs) != 4 {
		t.Fatalf("got %d", len(pkgs))
	}
	if pkgs[2]["name"] != "busybox" || pkgs[2]["raw_version_string"] != "1.36.1-r29" ||
		pkgs[2]["entity_id"] != "pkg:container:apk:busybox:1.36.1-r29" || pkgs[2]["packages_scope"] != "container" {
		t.Fatalf("%#v", pkgs[2])
	}
}
