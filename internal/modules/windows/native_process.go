package windows

import (
	"context"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// PowerShell helper: native image path via QueryFullProcessImageName, then CIM, then known maps.
const psResolveProcessPath = `
function Ensure-NativeProcType {
  if (-not ('NativeProc' -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class NativeProc {
  const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
  [DllImport("kernel32.dll", SetLastError=true)]
  static extern bool CloseHandle(IntPtr h);
  public static string GetImagePath(int pid) {
    IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (h == IntPtr.Zero) return null;
    try {
      var sb = new StringBuilder(1024);
      int size = sb.Capacity;
      if (QueryFullProcessImageName(h, 0, sb, ref size)) return sb.ToString(0, size);
      return null;
    } finally { CloseHandle(h); }
  }
}
"@
  }
}
function Resolve-ProcessImagePath {
  param([int]$ProcessId, [string]$Name, [string]$CimPath)
  Ensure-NativeProcType
  $result = [ordered]@{
    executable_path = $null
    path_source = $null
    path_status = 'unresolved'
    known_component = $null
  }
  if ($ProcessId -le 0) { $result.path_status = 'invalid_pid'; return [pscustomobject]$result }
  if ($Name -eq 'System' -or $Name -eq 'Idle' -or $Name -eq 'Registry') {
    $result.path_status = 'kernel_or_protected'
    $result.path_source = 'known_component_map'
    $result.known_component = $Name
    return [pscustomobject]$result
  }
  try {
    $native = [NativeProc]::GetImagePath($ProcessId)
    if ($native) {
      $result.executable_path = $native
      $result.path_source = 'QueryFullProcessImageName'
      $result.path_status = 'resolved'
      return [pscustomobject]$result
    }
  } catch {}
  try {
    $gp = Get-Process -Id $ProcessId -EA SilentlyContinue
    if ($gp -and $gp.Path) {
      $result.executable_path = $gp.Path
      $result.path_source = 'Get-Process.Path'
      $result.path_status = 'resolved'
      return [pscustomobject]$result
    }
  } catch {}
  if ($CimPath) {
    $result.executable_path = $CimPath
    $result.path_source = 'Win32_Process.ExecutablePath'
    $result.path_status = 'resolved'
    return [pscustomobject]$result
  }
  $result.path_status = 'access_denied_or_protected'
  $result.path_source = 'unresolved'
  return [pscustomobject]$result
}
`

func (m *Processes) Version() string { return "1.2.0" }

func (m *Processes) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := psResolveProcessPath + `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
Get-CimInstance Win32_Process | ForEach-Object {
  $resolved = Resolve-ProcessImagePath -ProcessId ([int]$_.ProcessId) -Name $_.Name -CimPath $_.ExecutablePath
  $rows += [PSCustomObject]@{
    ProcessId = [int]$_.ProcessId
    ParentProcessId = [int]$_.ParentProcessId
    Name = $_.Name
    ExecutablePath = $resolved.executable_path
    path_source = $resolved.path_source
    path_status = $resolved.path_status
    known_component = $resolved.known_component
    CommandLine = $_.CommandLine
    SessionId = $_.SessionId
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+truncate(out, 400)))
		common.Finish(&res, started, "error")
		return res
	}
	rows, err := decodeJSONRows(out)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	denied := 0
	resolved := 0
	native := 0
	for _, row := range rows {
		pid := asInt(row["ProcessId"])
		exe := asString(row["ExecutablePath"])
		status := asString(row["path_status"])
		src := asString(row["path_source"])
		cmdline := RedactSecrets(asString(row["CommandLine"]))
		rec := map[string]any{
			"entity_id":        entityProcess(pid),
			"entity_type":      "process",
			"pid":              pid,
			"ppid":             asInt(row["ParentProcessId"]),
			"name":             asString(row["Name"]),
			"executable_path":  nullIfEmpty(exe),
			"path_source":      nullIfEmpty(src),
			"path_status":      status,
			"command_line":     nullIfEmpty(cmdline),
			"session_id":       asInt(row["SessionId"]),
			"binary_entity_id": nil,
		}
		if kc := asString(row["known_component"]); kc != "" {
			rec["known_component"] = kc
		}
		if exe != "" {
			rec["binary_entity_id"] = entityBinary(exe)
			resolved++
			if src == "QueryFullProcessImageName" {
				native++
			}
		} else if status == "access_denied_or_protected" {
			denied++
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", rec, nil))
	}
	st := "success"
	if denied > 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "PROCESS_ACCESS_DENIED", "processes_unresolved="+stringify(denied)+"; native_resolved="+stringify(native)+"; path_resolved="+stringify(resolved)))
		st = "partial"
	}
	common.Finish(&res, started, st)
	return res
}

func (m *Services) Version() string { return "1.2.1" }

func (m *Services) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := `
$ErrorActionPreference = 'SilentlyContinue'
Get-CimInstance Win32_Service | ForEach-Object {
  $name = $_.Name
  $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
  $params = "$reg\Parameters"
  $props = Get-ItemProperty $reg -EA SilentlyContinue
  $dll = $null
  if (Test-Path $params) { $dll = (Get-ItemProperty $params -EA SilentlyContinue).ServiceDll }
  $img = $_.PathName
  $group = $null
  if ($img -match '(?i)\bsvchost\.exe\b.*?\s-k\s+(\S+)') { $group = $Matches[1] }
  # Win32_Service.ServicesDependedOn is often empty via CIM; Prefer registry DependOnService.
  $deps = @()
  if ($props.DependOnService) {
    $deps = @($props.DependOnService | Where-Object { $_ -and "$_".Trim() -ne '' })
  } elseif ($_.ServicesDependedOn) {
    foreach ($d in $_.ServicesDependedOn) { if ($d.Name) { $deps += $d.Name } }
  }
  $delayed = $null
  if ($null -ne $props.DelayedAutoStart) { $delayed = [bool]$props.DelayedAutoStart }
  $svcType = $null
  if ($null -ne $props.Type) { $svcType = [int]$props.Type }
  $launchProtected = $null
  if ($null -ne $props.LaunchProtected) { $launchProtected = [int]$props.LaunchProtected }
  $failureActions = $null
  if ($null -ne $props.FailureActions) { $failureActions = 'present' }
  $requiredPrivileges = $null
  if ($null -ne $props.RequiredPrivileges) { $requiredPrivileges = @($props.RequiredPrivileges) }
  $bin = $null
  if ($img -match '^"([^"]+)"') { $bin = $Matches[1] } elseif ($img) { $bin = ($img -split '\s+')[0] }
  $pathStatus = if ($bin) { 'resolved' } else { 'unresolved' }
  [PSCustomObject]@{
    entity_id = ('service:' + $name.ToLower())
    entity_type = 'service'
    service_name = $name
    display_name = $_.DisplayName
    state = $_.State
    start_type = $_.StartMode
    delayed_auto_start = $delayed
    service_type = $svcType
    service_account = $_.StartName
    process_id = [int]$_.ProcessId
    path_name = $img
    binary_path = $bin
    path_source = if ($bin) { 'Win32_Service.PathName' } else { $null }
    path_status = $pathStatus
    svchost_group = $group
    service_dll = $dll
    dependencies = $deps
    launch_protected = $launchProtected
    failure_actions = $failureActions
    required_privileges = $requiredPrivileges
    registry_path = "HKLM\SYSTEM\CurrentControlSet\Services\$name"
  }
} | ConvertTo-Json -Compress -Depth 5
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+truncate(out, 400)))
		common.Finish(&res, started, "error")
		return res
	}
	rows, err := decodeJSONRows(out)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	for _, row := range rows {
		if dll := asString(row["service_dll"]); dll != "" {
			row["service_dll"] = expandWindowsEnvLite(dll)
		}
		// PathName often embeds secrets (e.g. ...exe -password x); redact before emit.
		if pn := asString(row["path_name"]); pn != "" {
			row["path_name"] = RedactSecrets(pn)
		}
		if bp := asString(row["binary_path"]); bp != "" {
			row["binary_path"] = RedactSecrets(bp)
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", row, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

func expandWindowsEnvLite(s string) string {
	repl := []struct{ a, b string }{
		{"%SystemRoot%", `C:\Windows`},
		{"%systemroot%", `C:\Windows`},
		{"%windir%", `C:\Windows`},
		{"%WinDir%", `C:\Windows`},
	}
	out := s
	for _, r := range repl {
		out = strings.ReplaceAll(out, r.a, r.b)
	}
	return out
}
