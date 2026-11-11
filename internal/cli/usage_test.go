package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRoot()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestRuntimeErrorDoesNotPrintUsage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.openness")
	out, err := runRoot(t, "validate", missing)
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if strings.Contains(out, "Usage:") {
		t.Fatalf("runtime error printed usage:\n%s", out)
	}
}

func TestFlagErrorPrintsUsage(t *testing.T) {
	out, err := runRoot(t, "collect", "--no-such-flag")
	if err == nil {
		t.Fatal("expected a flag error")
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("flag error did not print usage:\n%s", out)
	}
}
