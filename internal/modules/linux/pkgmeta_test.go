package linux

import (
	"strings"
	"testing"
)

func TestParseDebianSource(t *testing.T) {
	n, v := ParseDebianSource("openssl")
	if n != "openssl" || v != nil {
		t.Fatalf("got %q %v", n, v)
	}
	n, v = ParseDebianSource("foo (1.2.3-1)")
	if n != "foo" || v != "1.2.3-1" {
		t.Fatalf("got %q %v", n, v)
	}
}

func TestParseDebianVersion(t *testing.T) {
	e, ver, rel := ParseDebianVersion("1:3.22.22-1")
	if e != "1" || ver != "3.22.22" || rel != "1" {
		t.Fatalf("got %v %q %q", e, ver, rel)
	}
}

func TestParseSourceRPM(t *testing.T) {
	n, v, r, ok := ParseSourceRPM("openssl-3.0.7-30.el9_2.src.rpm")
	if !ok || n != "openssl" || v != "3.0.7" || r != "30.el9_2" {
		t.Fatalf("got %v %q %q %q", ok, n, v, r)
	}
	n, v, r, ok = ParseSourceRPM("python3-setuptools-wheel-53.0.0-12.el9.src.rpm")
	if !ok || n != "python3-setuptools-wheel" || v != "53.0.0" || r != "12.el9" {
		t.Fatalf("got %v %q %q %q", ok, n, v, r)
	}
}

func TestParseAptPolicyOriginHTTP(t *testing.T) {
	sample := `
openssh-server:
  Installed: 1:8.9p1-3ubuntu0.10
  Candidate: 1:8.9p1-3ubuntu0.10
  Version table:
 *** 1:8.9p1-3ubuntu0.10 500
        500 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages
        100 /var/lib/dpkg/status
`
	r := parseAptPolicy(sample)
	if r["installed_from_repository"] != true {
		t.Fatalf("expected from_repo true, got %#v", r)
	}
	if r["repository_url"] != "http://archive.ubuntu.com/ubuntu" {
		t.Fatalf("url=%v", r["repository_url"])
	}
	if r["repository_suite"] != "jammy-updates" || r["repository_component"] != "main" {
		t.Fatalf("suite/comp=%v/%v", r["repository_suite"], r["repository_component"])
	}
	if r["repository_origin"] != "archive.ubuntu.com" {
		t.Fatalf("origin=%v", r["repository_origin"])
	}
}

func TestParseAptPolicyStatusOnlyUnknown(t *testing.T) {
	sample := `
foo:
  Installed: 1.0-1
  Candidate: 1.0-1
  Version table:
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`
	r := parseAptPolicy(sample)
	if r["installed_from_repository"] != nil {
		t.Fatalf("expected null from_repo, got %#v", r["installed_from_repository"])
	}
	if r["repository_origin"] != nil {
		t.Fatalf("must not invent local origin, got %v", r["repository_origin"])
	}
}

func TestOwnershipPathCandidatesUsrMerge(t *testing.T) {
	c := ownershipPathCandidates("/usr/bin/sshd")
	found := false
	for _, p := range c {
		if p == "/bin/sshd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /bin/sshd twin in %v", c)
	}
}

func TestRedactSecrets(t *testing.T) {
	in := "mysqld --password=supersecret -u root"
	out := RedactSecrets(in)
	if strings.Contains(out, "supersecret") {
		t.Fatalf("not redacted: %s", out)
	}
	if !strings.Contains(out, "***REDACTED***") {
		t.Fatalf("expected redaction marker: %s", out)
	}
}
