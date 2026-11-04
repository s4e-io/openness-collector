//go:build !windows

package windows

func observeWindowsRebootPending() map[string]any {
	return map[string]any{
		"reboot_pending_windows_update":  nil,
		"reboot_pending_cbs":             nil,
		"pending_file_rename_operations": nil,
		"pending_computer_rename":        nil,
		"reboot_pending":                 nil,
	}
}
