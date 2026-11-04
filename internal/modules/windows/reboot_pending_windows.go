//go:build windows

package windows

import (
	"golang.org/x/sys/windows/registry"
)

// observeWindowsRebootPending reads the three common reboot-needed signals and
// OR-aggregates them into reboot_pending. Observation only — no action.
func observeWindowsRebootPending() map[string]any {
	wu := registryKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`)
	cbs := registryKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`)
	pendingRename := registryValuePresent(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "PendingFileRenameOperations")
	pendingComputerRename := computerRenamePending()

	// Aggregate only WU+CBS for action cards; rename/file-rename are noisy signals kept separate.
	return map[string]any{
		"reboot_pending_windows_update":  wu,
		"reboot_pending_cbs":             cbs,
		"pending_file_rename_operations": pendingRename,
		"pending_computer_rename":        pendingComputerRename,
		"reboot_pending":                 wu || cbs,
	}
}

func registryKeyExists(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}

func registryValuePresent(root registry.Key, path, name string) bool {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if _, _, err := k.GetStringsValue(name); err == nil {
		return true
	}
	if _, _, err := k.GetStringValue(name); err == nil {
		return true
	}
	if _, _, err := k.GetIntegerValue(name); err == nil {
		return true
	}
	return false
}

func computerRenamePending() bool {
	active, err1 := readComputerName(`SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName`)
	pending, err2 := readComputerName(`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`)
	if err1 != nil || err2 != nil {
		return false
	}
	return active != "" && pending != "" && active != pending
}

func readComputerName(path string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ComputerName")
	return v, err
}
