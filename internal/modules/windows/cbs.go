package windows

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// CBSPackages collects Component-Based Servicing package evidence (not Get-HotFix).
type CBSPackages struct{}

func (m *CBSPackages) ID() string          { return "cbs_packages" }
func (m *CBSPackages) Version() string     { return "1.0.0" }
func (m *CBSPackages) Platforms() []string { return []string{"windows"} }

func (m *CBSPackages) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	script := `
$ErrorActionPreference = 'SilentlyContinue'
function Normalize-State($s) {
  if (-not $s) { return 'unknown' }
  $t = $s.ToString().ToLower()
  switch -Regex ($t) {
    'installed' { return 'installed' }
    'installpending|install pending' { return 'install_pending' }
    'staged' { return 'staged' }
    'superseded' { return 'superseded' }
    'partially' { return 'partially_installed' }
    'uninstallpending|uninstall pending' { return 'uninstall_pending' }
    'absent' { return 'absent' }
    default { return 'unknown' }
  }
}
$rows = @()
$dismErr = $null
try {
  $pkgs = Get-WindowsPackage -Online -EA Stop
  foreach ($p in $pkgs) {
    $ident = $p.PackageName
    $kb = $null
    if ($ident -match '(?i)KB(\d{6,8})') { $kb = 'KB' + $Matches[1] }
    $state = Normalize-State $p.PackageState
    $rows += [PSCustomObject]@{
      package_identity = $ident
      package_name = $ident
      kb_article_id = $kb
      version = $null
      architecture = $p.ReleaseType
      culture = $null
      public_key_token = $null
      release_type = [string]$p.ReleaseType
      state = $state
      install_time = if ($p.InstallTime) { $p.InstallTime.ToUniversalTime().ToString('o') } else { $null }
      permanence = $null
      applicability = $null
      restart_required = $null
      source = 'dism'
    }
  }
} catch {
  $dismErr = $_.Exception.Message
  # Registry fallback for installed package identities
  $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
  if (Test-Path $base) {
    Get-ChildItem $base -EA SilentlyContinue | ForEach-Object {
      $name = $_.PSChildName
      $props = Get-ItemProperty $_.PSPath -EA SilentlyContinue
      $kb = $null
      if ($name -match '(?i)KB(\d{6,8})') { $kb = 'KB' + $Matches[1] }
      $stateNum = $props.CurrentState
      $state = switch ($stateNum) {
        0 { 'absent' }
        4 { 'absent' }
        5 { 'staged' }
        6 { 'staged' }
        7 { 'partially_installed' }
        32 { 'install_pending' }
        48 { 'uninstall_pending' }
        64 { 'superseded' }
        80 { 'superseded' }
        112 { 'installed' }
        default { 'unknown' }
      }
      $rows += [PSCustomObject]@{
        package_identity = $name
        package_name = $name
        kb_article_id = $kb
        version = $null
        architecture = $null
        culture = $null
        public_key_token = $null
        release_type = $null
        state = $state
        install_time = $null
        permanence = $null
        applicability = $null
        restart_required = $null
        source = 'cbs_registry'
        cbs_current_state = $stateNum
      }
    }
  }
}
$wuReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$cbsReboot = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$pendingRename = $false
try {
  $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -EA SilentlyContinue
  if ($null -ne $sm -and $null -ne $sm.PendingFileRenameOperations) { $pendingRename = $true }
} catch {}
$pendingComputerRename = $false
try {
  $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -EA Stop).ComputerName
  $pending = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -EA Stop).ComputerName
  if ($active -and $pending -and ($active -ne $pending)) { $pendingComputerRename = $true }
} catch {}
# Aggregate only WU+CBS; pending rename flags stay observational/noisy.
$reboot = [bool]($wuReboot -or $cbsReboot)
@{
  status = if ($rows.Count -gt 0) { 'success' } elseif ($dismErr) { 'partial' } else { 'unavailable' }
  dism_error = $dismErr
  reboot_pending = $reboot
  reboot_pending_windows_update = [bool]$wuReboot
  reboot_pending_cbs = [bool]$cbsReboot
  pending_file_rename_operations = [bool]$pendingRename
  pending_computer_rename = [bool]$pendingComputerRename
  count = $rows.Count
  packages = $rows
} | ConvertTo-Json -Compress -Depth 6
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		msg := err.Error() + ": " + truncate(out, 400)
		code := "collection_error"
		if strings.Contains(strings.ToLower(msg), "timeout") {
			code = "DISM_TIMEOUT"
		}
		res.Errors = append(res.Errors, common.Err(m.ID(), code, msg))
		common.Finish(&res, started, "error")
		return res
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "CBS_PACKAGE_PARSE_ERROR", err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	if dismErr := asString(parsed["dism_error"]); dismErr != "" {
		res.Errors = append(res.Errors, common.Err(m.ID(), "CBS_STORE_UNAVAILABLE", dismErr))
	}
	switch pkgs := parsed["packages"].(type) {
	case []any:
		for _, p := range pkgs {
			pm, ok := p.(map[string]any)
			if !ok {
				continue
			}
			state := strings.ToLower(asString(pm["state"]))
			// Honesty: do not present staged/superseded as installed.
			pm["entity_type"] = "cbs_package"
			pm["entity_id"] = "cbs:" + asString(pm["package_identity"])
			pm["is_active_fix"] = state == "installed"
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", pm, nil))
		}
	case map[string]any:
		pkgs["entity_type"] = "cbs_package"
		pkgs["entity_id"] = "cbs:" + asString(pkgs["package_identity"])
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", pkgs, nil))
	}

	// Always emit reboot observation flags (true/false) for remediation cards.
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", map[string]any{
		"entity_type":                    "servicing_context",
		"entity_id":                      "servicing:reboot_pending",
		"reboot_pending":                 asBool(parsed["reboot_pending"]),
		"reboot_pending_windows_update":  asBool(parsed["reboot_pending_windows_update"]),
		"reboot_pending_cbs":             asBool(parsed["reboot_pending_cbs"]),
		"pending_file_rename_operations": asBool(parsed["pending_file_rename_operations"]),
		"pending_computer_rename":        asBool(parsed["pending_computer_rename"]),
		"source":                         "windows_reboot_signals",
	}, nil))

	status := "success"
	switch asString(parsed["status"]) {
	case "partial":
		status = "partial"
	case "unavailable":
		if len(res.Evidence) == 0 {
			res.Errors = append(res.Errors, common.Err(m.ID(), "CBS_STORE_UNAVAILABLE", "no CBS packages collected"))
			status = "unavailable"
		} else {
			status = "partial"
		}
	}
	if len(res.Evidence) == 0 && status == "success" {
		status = "unavailable"
	}
	common.Finish(&res, started, status)
	return res
}
