package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInferOriginFromListName(t *testing.T) {
	o := inferOriginFromListName("archive.ubuntu.com_ubuntu_dists_jammy-updates_main_binary-amd64_Packages")
	if o.Suite != "jammy-updates" || o.Component != "main" {
		t.Fatalf("%#v", o)
	}
	if o.URL != "http://archive.ubuntu.com/ubuntu" {
		t.Fatalf("url %#v", o.URL)
	}
	if o.Origin != "Ubuntu" {
		t.Fatalf("origin %#v", o.Origin)
	}
	o2 := inferOriginFromListName("ports.ubuntu.com_ubuntu-ports_dists_jammy-security_main_binary-arm64_Packages.lz4")
	if o2.Suite != "jammy-security" || o2.Component != "main" {
		t.Fatalf("%#v", o2)
	}
	if o2.URL != "http://ports.ubuntu.com/ubuntu-ports" {
		t.Fatalf("url %#v", o2.URL)
	}
}

func TestApplyAptOriginToPackage(t *testing.T) {
	idx := &aptListsIndex{
		ByNVRA: map[string]aptListOrigin{
			"openssl|3.0.2-0ubuntu1.1|amd64": {
				URL: "http://security.ubuntu.com/ubuntu", Origin: "Ubuntu", Label: "Ubuntu",
				Suite: "jammy-security", Component: "main", RepoID: "security.ubuntu.com_ubuntu_dists_jammy-security_main_binary-amd64",
			},
		},
		Candidates: map[string]aptCandidate{
			"openssl|amd64": {
				Version: "3.0.2-0ubuntu1.18",
				Origin: aptListOrigin{
					URL: "http://security.ubuntu.com/ubuntu", Origin: "Ubuntu", Label: "Ubuntu",
					Suite: "jammy-security", Component: "main",
				},
			},
		},
	}
	v := map[string]any{
		"name": "openssl", "raw_version_string": "3.0.2-0ubuntu1.1", "architecture": "amd64",
		"installed_from_repository": nil,
	}
	applyAptOriginToPackage(v, idx)
	if v["installed_from_repository"] != true {
		t.Fatalf("%#v", v)
	}
	if v["security_repository"] != true {
		t.Fatalf("security flag %#v", v)
	}
	if v["highest_list_version"] != "3.0.2-0ubuntu1.18" {
		t.Fatalf("highest_list_version %#v", v["highest_list_version"])
	}
	co, _ := v["highest_list_origin"].(map[string]any)
	if co["suite"] != "jammy-security" || co["esm"] != false {
		t.Fatalf("highest_list_origin %#v", co)
	}
	// unknown must stay null for installed_from_repository; candidate still filled if present
	u := map[string]any{"name": "localdeb", "raw_version_string": "1.0", "architecture": "amd64", "installed_from_repository": nil}
	applyAptOriginToPackage(u, idx)
	if u["installed_from_repository"] != nil {
		t.Fatalf("must remain null, got %#v", u["installed_from_repository"])
	}
	if u["repository_metadata_status"] != "not_in_apt_lists" {
		t.Fatalf("%#v", u)
	}
	if u["highest_list_version"] != nil {
		t.Fatalf("no highest_list_version for localdeb, got %#v", u["highest_list_version"])
	}
}

func TestConsiderAptCandidateKeepsHighest(t *testing.T) {
	idx := &aptListsIndex{Candidates: map[string]aptCandidate{}}
	oOld := aptListOrigin{Suite: "jammy", Origin: "Ubuntu"}
	oNew := aptListOrigin{Suite: "jammy-security", Origin: "Ubuntu"}
	considerAptCandidate(idx, "libssl3", "amd64", "3.0.2-0ubuntu1.1", oOld)
	considerAptCandidate(idx, "libssl3", "amd64", "3.0.2-0ubuntu1.18", oNew)
	considerAptCandidate(idx, "libssl3", "amd64", "3.0.2-0ubuntu1.10", oOld)
	c := idx.Candidates["libssl3|amd64"]
	if c.Version != "3.0.2-0ubuntu1.18" {
		t.Fatalf("want 3.0.2-0ubuntu1.18 got %s", c.Version)
	}
	if c.Origin.Suite != "jammy-security" {
		t.Fatalf("suite %#v", c.Origin.Suite)
	}
}

func TestCompareDebVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1.1", 1},
		{"1:1.0", "1.0", 1},
		{"1.0~~", "1.0", -1},
		{"2.0", "1.9", 1},
	}
	for _, tc := range cases {
		got := compareDebVersion(tc.a, tc.b)
		if got != tc.want {
			t.Fatalf("compare(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestLoadAptPackageOriginsEmptyDir(t *testing.T) {
	// Should not panic when lists missing
	_ = loadAptPackageOrigins()
}

func TestParseAptReleaseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Release")
	_ = os.WriteFile(path, []byte("Origin: Ubuntu\nLabel: Ubuntu\nSuite: jammy\nCodename: jammy\n"), 0o644)
	o := parseAptReleaseFile(path)
	if o.Origin != "Ubuntu" || o.Suite != "jammy" {
		t.Fatalf("%#v", o)
	}
}
