package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENNESS_CONFIG_DIR", dir)

	if err := Save(Credentials{Token: "test-token-value-with-enough-length-0123456789", Source: "test"}); err != nil {
		t.Fatal(err)
	}
	path, err := CredentialsPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("path=%s dir=%s", path, dir)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Unix permission bits are not meaningful the same way on Windows ACLs.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("credentials should not be group/world readable: %v", info.Mode())
	}
	loaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Token != "test-token-value-with-enough-length-0123456789" {
		t.Fatalf("token=%q", loaded.Token)
	}
	tok, src, err := ResolveToken("", "OPENNESS_API_KEY")
	if err != nil || src != "credentials" || tok != loaded.Token {
		t.Fatalf("resolve tok=%q src=%q err=%v", tok, src, err)
	}
	t.Setenv("OPENNESS_API_KEY", "env-token-value-with-enough-length-0123456789")
	tok, src, err = ResolveToken("", "OPENNESS_API_KEY")
	if err != nil || src != "env:OPENNESS_API_KEY" || tok != "env-token-value-with-enough-length-0123456789" {
		t.Fatalf("env resolve tok=%q src=%q err=%v", tok, src, err)
	}
	tok, src, err = ResolveToken("flag-token-value-with-enough-length-0123456789", "OPENNESS_API_KEY")
	if err != nil || src != "flag" {
		t.Fatalf("flag resolve tok=%q src=%q err=%v", tok, src, err)
	}
	if err := Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); !os.IsNotExist(err) {
		t.Fatalf("expected not exist after delete, got %v", err)
	}
}
