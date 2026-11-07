// Package procutil starts external commands that cannot outlive their
// context: each child runs in its own process group and the whole group is
// killed when the context is cancelled, so a hung helper (rpm, dpkg-query, a
// shell wrapper and its children) never keeps the collector waiting.
package procutil

import (
	"context"
	"os/exec"
	"time"
)

// WaitDelay bounds how long Wait keeps waiting for output pipes after the
// process group was killed (a grandchild that escaped the group could still
// hold them open).
const WaitDelay = 2 * time.Second

// Command is exec.CommandContext with process-group kill on cancel.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	setGroupKill(cmd)
	cmd.WaitDelay = WaitDelay
	return cmd
}
