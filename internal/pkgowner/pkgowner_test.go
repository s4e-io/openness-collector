package pkgowner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveDpkg(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/lib/dpkg/info/nginx-core.list", "/.\n/usr\n/usr/sbin\n/usr/sbin/nginx\n")
	write(t, root, "var/lib/dpkg/info/libssl3t64:amd64.list", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3\n")
	write(t, root, "var/lib/dpkg/info/vendor-suite.list", "/opt/vendor-suite/embedded/bin/postgres\n")
	write(t, root, "var/lib/dpkg/info/nginx-core.md5sums", "ignored\n")
	write(t, root, "var/lib/dpkg/status",
		"Package: nginx-core\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.24.0-2ubuntu7.5\nDescription: x\n continued\n\n"+
			"Package: libssl3t64\nStatus: install ok installed\nArchitecture: i386\nVersion: 3.0.13-0ubuntu3.9\n\n"+
			"Package: libssl3t64\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3.6\n\n"+
			"Package: vendor-suite\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 6.4.0\n\n")

	res := Resolve(context.Background(), root, []string{
		"/usr/sbin/nginx",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/opt/vendor-suite/embedded/bin/postgres",
		"/opt/handmade/bin/postgres",
		"/usr/sbin",
	})
	if !reflect.DeepEqual(res.Managers, []string{"dpkg"}) {
		t.Fatalf("managers = %v", res.Managers)
	}
	o := res.Owners["/usr/sbin/nginx"]
	if o.Name != "nginx-core" || o.EntityID() != "pkg:dpkg:nginx-core:amd64:1.24.0-2ubuntu7.5" || o.Path != "/usr/sbin/nginx" {
		t.Fatalf("nginx owner = %+v", o)
	}
	// The architecture in the list file name picks the matching stanza.
	if o := res.Owners["/usr/lib/x86_64-linux-gnu/libcrypto.so.3"]; o.Arch != "amd64" || o.Version != "3.0.13-0ubuntu3.6" {
		t.Fatalf("libcrypto owner = %+v", o)
	}
	// Owner known by name; no installed stanza, so no entity id is invented.
	if o := res.Owners["/opt/vendor-suite/embedded/bin/postgres"]; o.Name != "vendor-suite" || o.EntityID() != "" {
		t.Fatalf("embedded owner = %+v", o)
	}
	if _, ok := res.Owners["/opt/handmade/bin/postgres"]; ok {
		t.Fatal("unowned file got an owner")
	}
}

func TestResolveDpkgUsrMergeTwin(t *testing.T) {
	root := t.TempDir()
	write(t, root, "var/lib/dpkg/info/openssh-server.list", "/usr/sbin/sshd\n")
	res := Resolve(context.Background(), root, []string{"/sbin/sshd"})
	if o := res.Owners["/sbin/sshd"]; o.Name != "openssh-server" || o.Path != "/sbin/sshd" {
		t.Fatalf("owner = %+v", o)
	}
}

func TestResolveApk(t *testing.T) {
	root := t.TempDir()
	write(t, root, "lib/apk/db/installed",
		"P:nginx\nV:1.26.2-r0\nA:x86_64\nF:usr\nF:usr/sbin\nR:nginx\na:0:0:755\nF:etc/nginx\nR:nginx.conf\n\n"+
			"P:busybox\r\nF:bin\r\nR:busybox\r\nV:1.36.1-r29\r\nA:x86_64\r\n\r\n")
	res := Resolve(context.Background(), root, []string{"/usr/sbin/nginx", "/bin/busybox", "/usr/local/bin/tool"})
	if !reflect.DeepEqual(res.Managers, []string{"apk"}) {
		t.Fatalf("managers = %v", res.Managers)
	}
	if o := res.Owners["/usr/sbin/nginx"]; o.EntityID() != "pkg:apk:nginx:x86_64:1.26.2-r0" {
		t.Fatalf("nginx owner = %+v", o)
	}
	// Version and architecture after the file lines still belong to the stanza.
	if o := res.Owners["/bin/busybox"]; o.EntityID() != "pkg:apk:busybox:x86_64:1.36.1-r29" {
		t.Fatalf("busybox owner = %+v", o)
	}
	if len(res.Owners) != 2 {
		t.Fatalf("owners = %v", res.Owners)
	}
}

func TestResolveSharedSpelling(t *testing.T) {
	// A symlink and its target are both asked about; both get the owner.
	dir := t.TempDir()
	target := filepath.Join(dir, "lib", "libcrypto.so.3")
	write(t, dir, "lib/libcrypto.so.3", "x")
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "usr/lib/libcrypto.so.3")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable")
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write(t, root, "var/lib/dpkg/info/libssl3.list", resolved+"\n")
	res := Resolve(context.Background(), root, []string{link, target, link})
	for _, p := range []string{link, target} {
		if o := res.Owners[p]; o.Name != "libssl3" || o.Path != p {
			t.Fatalf("%s owner = %+v", p, o)
		}
	}
}

func TestResolveNoDatabase(t *testing.T) {
	res := Resolve(context.Background(), t.TempDir(), []string{"/usr/sbin/nginx"})
	if len(res.Managers) != 0 || len(res.Owners) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestParseRPMOwners(t *testing.T) {
	files := []string{"/usr/sbin/nginx", "/opt/x/bin/tool", "/usr/bin/docker"}
	out := "nginx-core\t2\t1.20.1\t20.el9\tx86_64\n" +
		"file /opt/x/bin/tool is not owned by any package\n" +
		"docker-ce-cli\t(none)\t28.5.0\t1.el9\tx86_64\n"
	found, ok := parseRPMOwners(out, files)
	if !ok || len(found) != 2 {
		t.Fatalf("found = %v ok = %v", found, ok)
	}
	if o := found["/usr/sbin/nginx"]; o.EntityID() != "pkg:rpm:nginx-core:x86_64:2:1.20.1-20.el9" {
		t.Fatalf("nginx = %+v", o)
	}
	if o := found["/usr/bin/docker"]; o.EntityID() != "pkg:rpm:docker-ce-cli:x86_64:28.5.0-1.el9" {
		t.Fatalf("docker = %+v", o)
	}
	// A row count that does not match the files cannot be paired.
	if _, ok := parseRPMOwners(out+"extra\t(none)\t1\t1\tnoarch\n", files); ok {
		t.Fatal("mismatched rows were paired")
	}
}

func TestOwnerValue(t *testing.T) {
	v := Owner{Manager: "dpkg", Name: "vendor-suite", Path: "/opt/vendor-suite/bin/x"}.Value()
	if v["entity_id"] != nil || v["version"] != nil || v["name"] != "vendor-suite" {
		t.Fatalf("value = %#v", v)
	}
}
