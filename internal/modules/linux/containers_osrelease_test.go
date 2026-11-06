package linux

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const debian11OSRelease = `PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
`

const rocky9OSRelease = `NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
PRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"
`

func TestReadContainerOSReleaseRootfs(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root string)
		want  map[string]any
	}{
		{
			name: "regular etc file",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "etc/os-release"), rocky9OSRelease, 0o644)
			},
			want: map[string]any{"id": "rocky", "id_like": "rhel centos fedora", "version_id": "9.3",
				"pretty_name": "Rocky Linux 9.3 (Blue Onyx)", "source": "rootfs", "source_file": "/etc/os-release"},
		},
		{
			name: "relative symlink to usr lib",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "usr/lib/os-release"), debian11OSRelease, 0o644)
				if err := os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release")); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]any{"id": "debian", "version_id": "11", "version_codename": "bullseye",
				"source": "rootfs", "source_file": "/etc/os-release"},
		},
		{
			name: "absolute symlink is re-rooted",
			setup: func(t *testing.T, root string) {
				if runtime.GOOS == "windows" {
					t.Skip("absolute symlinks inside a rootfs are a Unix layout")
				}
				writeFile(t, filepath.Join(root, "usr/lib/os-release"), debian11OSRelease, 0o644)
				if err := os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc/os-release")); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]any{"id": "debian", "version_codename": "bullseye", "source_file": "/etc/os-release"},
		},
		{
			name: "fallback to usr lib",
			setup: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, "usr/lib/os-release"), debian11OSRelease, 0o644)
			},
			want: map[string]any{"id": "debian", "source_file": "/usr/lib/os-release"},
		},
		{
			name:  "scratch image",
			setup: func(t *testing.T, root string) {},
			want:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, root)
			got := readContainerOSRelease(t.Context(), "", "", root)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("want nil, got %v", got)
				}
				return
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("%s=%v want %v (%v)", k, got[k], v, got)
				}
			}
		})
	}
}

func TestReadContainerOSReleaseRootfsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../../../../../etc/os-release", filepath.Join(root, "etc/os-release")); err != nil {
		t.Fatal(err)
	}
	if got := readContainerOSRelease(t.Context(), "", "", root); got != nil {
		t.Fatalf("escaping link must not be read: %v", got)
	}
}

// The runtime_cp path: /etc/os-release comes back as a symlink (docker cp
// does not follow it), so the collector must skip it and read
// /usr/lib/os-release; the record also carries the dpkg source package.
func TestContainersRuntimeCopyOSRelease(t *testing.T) {
	skipWithoutShellFakes(t)
	dir := t.TempDir()
	osr := filepath.Join(dir, "osr")
	writeFile(t, osr, debian11OSRelease, 0o644)
	status := filepath.Join(dir, "status")
	writeFile(t, status, "Package: libssl1.1\nStatus: install ok installed\nArchitecture: arm64\nSource: openssl\nVersion: 1.1.1n-0+deb11u5\n\n"+
		"Package: bsdutils\nStatus: install ok installed\nArchitecture: arm64\nSource: util-linux (2.36.1-8+deb11u1)\nVersion: 1:2.36.1-8+deb11u1\n", 0o644)
	shim := `#!/bin/sh
case "$1" in
ps) echo '{"ID":"c0000000000002","Names":"deb","Image":"debian:11","State":"running"}';;
inspect) echo '[{"Id":"c0000000000002","Name":"/deb","Config":{"Image":"debian:11"},"Image":"sha256:bb"}]';;
image) echo '[]';;
cp) case "$2" in
  *:/etc/os-release) ln -s ../usr/lib/os-release "$3";;
  *:/usr/lib/os-release) cp ` + osr + ` "$3";;
  *dpkg/status) cp ` + status + ` "$3";;
  *) exit 1;;
  esac;;
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
	osrV, _ := v["os_release"].(map[string]any)
	if osrV["id"] != "debian" || osrV["version_id"] != "11" || osrV["version_codename"] != "bullseye" ||
		osrV["source"] != "runtime_cp" || osrV["source_file"] != "/usr/lib/os-release" ||
		!strings.Contains(asString(osrV["pretty_name"]), "bullseye") {
		t.Fatalf("os_release=%v", v["os_release"])
	}
	pkgs, _ := v["packages"].([]map[string]any)
	if len(pkgs) != 2 || pkgs[0]["source_package"] != "openssl" || pkgs[0]["source_version"] != nil ||
		pkgs[1]["source_package"] != "util-linux" || pkgs[1]["source_version"] != "2.36.1-8+deb11u1" {
		t.Fatalf("packages=%v", pkgs)
	}
}
