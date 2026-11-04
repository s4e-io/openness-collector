package windows

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	in := `tool.exe --password secret123 --token abc Authorization: Bearer xyz`
	out := RedactSecrets(in)
	if strings.Contains(out, "secret123") || strings.Contains(out, "xyz") {
		t.Fatalf("expected redaction, got %q", out)
	}
	if !strings.Contains(out, "***REDACTED***") {
		t.Fatalf("expected redaction marker, got %q", out)
	}
}

func TestParseImagePath(t *testing.T) {
	p, a := parseImagePath(`"C:\Windows\system32\svchost.exe" -k LocalService -p`)
	if !strings.EqualFold(p, `C:\Windows\system32\svchost.exe`) {
		t.Fatalf("path=%q", p)
	}
	if g := svchostGroupFromArgs(a); g != "LocalService" {
		t.Fatalf("group=%q args=%q", g, a)
	}
}
