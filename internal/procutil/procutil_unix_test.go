//go:build !windows

package procutil

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A shell that forks a long sleep and waits: killing only the shell would
// leave the sleep holding stdout open and Output() blocked.
func TestCommandKillsWholeGroup(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := "sleep 300 & echo $! > " + pidFile + "; wait"
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Command(ctx, "sh", "-c", script).Output()
	if err == nil {
		t.Fatal("expected an error after cancel")
	}
	if d := time.Since(start); d > WaitDelay+2*time.Second {
		t.Fatalf("Output returned after %s, want prompt return", d)
	}
	b, rerr := os.ReadFile(pidFile)
	if rerr != nil {
		t.Fatalf("child pid: %v", rerr)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("grandchild %d still alive after cancel", pid)
}
