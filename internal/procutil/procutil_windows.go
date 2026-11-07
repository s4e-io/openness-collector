//go:build windows

package procutil

import "os/exec"

// setGroupKill keeps the default Cancel (Process.Kill) on Windows; WaitDelay
// still bounds the wait for pipes held by descendants.
func setGroupKill(cmd *exec.Cmd) {}
