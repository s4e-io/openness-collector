package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/procutil"
	"github.com/s4e-io/openness-collector/internal/schema"
)

func runPowerShell(ctx context.Context, script string) (string, error) {
	if err := requirePowerShell3(ctx); err != nil {
		return "", err
	}
	cmd := procutil.Command(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// minPowerShellMajor is the oldest Windows PowerShell the module scripts run on.
// They rely on ConvertTo-Json/ConvertFrom-Json, [ordered], [PSCustomObject]
// and Add-Member -NotePropertyName, none of which exist in PowerShell 2.0 (the
// Windows 7 / Server 2008 R2 default). Without this check those scripts fail
// with a bare exit status, or exit 0 with empty output that reads as "nothing
// found" because most of them run with ErrorActionPreference SilentlyContinue.
const minPowerShellMajor = 3

var (
	psVersionMu    sync.Mutex
	psVersionMajor int // 0 = not probed yet or probe failed
	probePSMajorFn = probePowerShellMajor
)

// errPowerShellTooOld is returned by runPowerShell on PowerShell 1.x/2.x hosts.
var errPowerShellTooOld = errors.New("PowerShell 3.0 or later required")

func requirePowerShell3(ctx context.Context) error {
	psVersionMu.Lock()
	if psVersionMajor == 0 {
		if m, err := probePSMajorFn(ctx); err == nil && m > 0 {
			psVersionMajor = m
		}
	}
	m := psVersionMajor
	psVersionMu.Unlock()
	if m > 0 && m < minPowerShellMajor {
		return fmt.Errorf("%w (found %d.x; install WMF 3.0 or later)", errPowerShellTooOld, m)
	}
	return nil
}

// probePowerShellMajor reports the major version of powershell.exe. PowerShell
// 1.0 has no $PSVersionTable and reports 1.
func probePowerShellMajor(ctx context.Context) (int, error) {
	pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := procutil.Command(pctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"if ($PSVersionTable) { $PSVersionTable.PSVersion.Major } else { 1 }")
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return parsePSMajor(string(out))
}

func parsePSMajor(out string) (int, error) {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return 0, errors.New("empty PowerShell version output")
	}
	return strconv.Atoi(fields[len(fields)-1])
}

type OSInventory struct{}

func (m *OSInventory) ID() string          { return "os_inventory" }
func (m *OSInventory) Version() string     { return "1.2.0" }
func (m *OSInventory) Platforms() []string { return []string{"windows"} }

// Run is implemented in os_inventory.go (CIM → registry PS → native registry).

// Applications collects the installed applications; Probes are the files to check for
// the applications they name (collect --file-probes).
type Applications struct {
	Probes []FileProbe
}

func (m *Applications) ID() string          { return "applications" }
func (m *Applications) Platforms() []string { return []string{"windows"} }

// Run and Version implemented in applications.go

type Patches struct{}

func (m *Patches) ID() string          { return "patches" }
func (m *Patches) Version() string     { return "1.1.0" }
func (m *Patches) Platforms() []string { return []string{"windows"} }

func (m *Patches) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	// Secondary cross-check only; primary installed update evidence is cbs_packages.
	script := `
Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy | ForEach-Object {
  [PSCustomObject]@{
    hotfix_id = $_.HotFixID
    description = $_.Description
    installed_on = $_.InstalledOn
    installed_by = $_.InstalledBy
    source = 'get_hotfix'
    evidence_role = 'secondary_crosscheck'
  }
} | ConvertTo-Json -Compress
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+out))
		common.Finish(&res, started, "error")
		return res
	}
	if out == "" || out == "null" {
		common.Finish(&res, started, "success")
		return res
	}
	rows, err := decodeJSONRows(out)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	for _, row := range rows {
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", row, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

type MissingUpdates struct{}

func (m *MissingUpdates) ID() string          { return "missing_updates" }
func (m *MissingUpdates) Version() string     { return "1.3.0" }
func (m *MissingUpdates) Platforms() []string { return []string{"windows"} }

func (m *MissingUpdates) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	script := `
$ErrorActionPreference = 'Stop'
$criteria = "IsInstalled=0 and Type='Software'"
$startedAt = (Get-Date).ToUniversalTime().ToString('o')
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $serviceID = $null
  $serviceName = $null
  $isDefault = $null
  $serverSelection = $null
  try {
    $serviceID = $searcher.ServiceID
    $serverSelection = [string]$searcher.ServerSelection
  } catch {}
  try {
    $mus = New-Object -ComObject Microsoft.Update.ServiceManager
    foreach ($svc in $mus.Services) {
      if ($serviceID -and ($svc.ServiceID -eq $serviceID)) {
        $serviceName = $svc.Name
        $isDefault = [bool]$svc.IsDefaultAUService
      }
    }
    if (-not $serviceName) {
      foreach ($svc in $mus.Services) {
        if ($svc.IsDefaultAUService) {
          $serviceID = $svc.ServiceID
          $serviceName = $svc.Name
          $isDefault = $true
        }
      }
    }
  } catch {}
  $wsus = $null
  $wsusStatus = $null
  $useWUServer = $null
  try {
    $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -EA SilentlyContinue
    if ($au) { $useWUServer = [bool]$au.UseWUServer }
    $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -EA SilentlyContinue
    if ($wu) { $wsus = $wu.WUServer; $wsusStatus = $wu.WUStatusServer }
  } catch {}
  $result = $searcher.Search($criteria)
  $completedAt = (Get-Date).ToUniversalTime().ToString('o')
  $rows = @()
  # First pass: identity + supersedes graph edges from WUA (IUpdate.SupersededUpdateIDs).
  $byId = @{}
  foreach ($u in $result.Updates) {
    $kbs = @(); foreach ($kb in $u.KBArticleIDs) { $kbs += [string]$kb }
    $products = @(); $classifications = @(); $categories = @()
    foreach ($c in $u.Categories) {
      $t = [string]$c.Type
      $n = $c.Name
      if ($t -eq 'Product') { $products += $n }
      elseif ($t -eq 'UpdateClassification') { $classifications += $n }
      else { $categories += $n }
    }
    $supersedesIds = $null
    $supersedesIdsRead = $false
    try {
      $supersedesIds = @()
      foreach ($sid in $u.SupersededUpdateIDs) { $supersedesIds += [string]$sid }
      $supersedesIdsRead = $true
    } catch {
      $supersedesIds = $null
      $supersedesIdsRead = $false
    }
    $uid = [string]$u.Identity.UpdateID
    $row = [PSCustomObject]@{
      update_id = $uid
      revision_number = $u.Identity.RevisionNumber
      title = $u.Title
      kb_article_ids = $kbs
      products = $products
      classifications = $classifications
      categories = $categories
      msrc_severity = $u.MsrcSeverity
      is_installed = $false
      is_downloaded = [bool]$u.IsDownloaded
      is_hidden = [bool]$u.IsHidden
      is_mandatory = [bool]$u.IsMandatory
      is_uninstallable = [bool]$u.IsUninstallable
      is_beta = [bool]$u.IsBeta
      is_superseded = [bool]$u.IsSuperseded
      reboot_required = [bool]$u.RebootRequired
      last_deployment_change_time = if ($u.LastDeploymentChangeTime) { ([datetime]$u.LastDeploymentChangeTime).ToUniversalTime().ToString('o') } else { $null }
      supersedes_update_ids = $supersedesIds
      supersedes_update_ids_observed = [bool]$supersedesIdsRead
      supersedes_kb_article_ids = $null
      supersedes_kb_partial = $null
      supersedes_kb_scope = 'pending_set_only'
      superseded_by_update_ids = $null
      superseded_by_kb_article_ids = $null
      superseded_by_scope = 'pending_set_only'
    }
    $rows += $row
    $byId[$uid] = $row
  }
  # Second pass: KB edges only inside this pending set; unresolved stays null (not []).
  # supersedes_kb_partial=true when some supersede update_ids resolved and some did not.
  foreach ($row in $rows) {
    if (-not $row.supersedes_update_ids_observed -or $null -eq $row.supersedes_update_ids) { continue }
    $kbOut = @()
    $resolvedCount = 0
    $total = @($row.supersedes_update_ids).Count
    foreach ($sid in @($row.supersedes_update_ids)) {
      if ($byId.ContainsKey($sid)) {
        $resolvedCount++
        foreach ($kb in $byId[$sid].kb_article_ids) { if ($kb -and ($kbOut -notcontains $kb)) { $kbOut += $kb } }
        if ($null -eq $byId[$sid].superseded_by_update_ids) { $byId[$sid].superseded_by_update_ids = @() }
        $rev = @($byId[$sid].superseded_by_update_ids) + @($row.update_id)
        $byId[$sid].superseded_by_update_ids = @($rev | Select-Object -Unique)
        if ($null -eq $byId[$sid].superseded_by_kb_article_ids) { $byId[$sid].superseded_by_kb_article_ids = @() }
        $revKb = @($byId[$sid].superseded_by_kb_article_ids)
        foreach ($kb in $row.kb_article_ids) { if ($kb -and ($revKb -notcontains $kb)) { $revKb += $kb } }
        $byId[$sid].superseded_by_kb_article_ids = $revKb
      }
    }
    if ($total -eq 0) {
      $row.supersedes_kb_article_ids = @()
      $row.supersedes_kb_partial = $false
    } elseif ($resolvedCount -eq 0) {
      $row.supersedes_kb_article_ids = $null
      $row.supersedes_kb_partial = $null
    } else {
      $row.supersedes_kb_article_ids = $kbOut
      $row.supersedes_kb_partial = ($resolvedCount -lt $total)
    }
  }
  $history = @()
  try {
    $hc = $searcher.GetTotalHistoryCount()
    $take = [Math]::Min(50, $hc)
    if ($take -gt 0) {
      $hist = $searcher.QueryHistory(0, $take)
      foreach ($h in $hist) {
        $history += [PSCustomObject]@{
          date = $h.Date.ToUniversalTime().ToString('o')
          title = $h.Title
          operation = [string]$h.Operation
          result_code = [string]$h.ResultCode
          hresult = $h.HResult
          update_id = if ($h.UpdateIdentity) { $h.UpdateIdentity.UpdateID } else { $null }
          revision_number = if ($h.UpdateIdentity) { $h.UpdateIdentity.RevisionNumber } else { $null }
        }
      }
    }
  } catch {}
  @{
    status = 'success'
    update_context = [PSCustomObject]@{
      entity_type = 'update_context'
      entity_id = 'wua:search_context'
      service_id = $serviceID
      service_name = $serviceName
      is_default_au_service = $isDefault
      server_selection = $serverSelection
      wsus_server = $wsus
      wsus_status_server = $wsusStatus
      use_wuserver = $useWUServer
      search_criteria = $criteria
      search_started_at = $startedAt
      search_completed_at = $completedAt
      result_code = 'succeeded'
      hresult = 0
      reboot_required = $null
    }
    count = $rows.Count
    updates = $rows
    history = $history
  } | ConvertTo-Json -Compress -Depth 6
} catch {
  $msg = $_.Exception.Message
  $code = 'WUA_SOURCE_UNREACHABLE'
  if ($msg -match '(?i)disabled|0x8024000[cC]|service') { $code = 'WUA_SERVICE_DISABLED' }
  if ($msg -match '(?i)timeout') { $code = 'WUA_SEARCH_TIMEOUT' }
  @{ status = 'error'; error = $msg; error_code = $code } | ConvertTo-Json -Compress
}
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+truncate(out, 400)))
		common.Finish(&res, started, "error")
		return res
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	if parsed["status"] == "error" {
		code := asString(parsed["error_code"])
		if code == "" {
			code = "unavailable"
		}
		res.Errors = append(res.Errors, common.Err(m.ID(), code, stringify(parsed["error"])))
		common.Finish(&res, started, "unavailable")
		return res
	}
	if ctxMap, ok := parsed["update_context"].(map[string]any); ok {
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", ctxMap, nil))
	}
	switch updates := parsed["updates"].(type) {
	case []any:
		for _, u := range updates {
			val := u
			if m, ok := u.(map[string]any); ok {
				val = enrichWUAUpdateRow(m)
			}
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", val, nil))
		}
	case map[string]any:
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", enrichWUAUpdateRow(updates), nil))
	}
	switch history := parsed["history"].(type) {
	case []any:
		for _, h := range history {
			if hm, ok := h.(map[string]any); ok {
				hm["entity_type"] = "update_history"
				res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", hm, nil))
			}
		}
	case map[string]any:
		history["entity_type"] = "update_history"
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", history, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

type Services struct{}

func (m *Services) ID() string          { return "services" }
func (m *Services) Platforms() []string { return []string{"windows"} }

// Version/Run implemented in native_process.go

type Processes struct{}

func (m *Processes) ID() string          { return "processes" }
func (m *Processes) Platforms() []string { return []string{"windows"} }

// Version/Run implemented in native_process.go

type ListeningPorts struct{}

func (m *ListeningPorts) ID() string          { return "listening_ports" }
func (m *ListeningPorts) Version() string     { return "1.1.0" }
func (m *ListeningPorts) Platforms() []string { return []string{"windows"} }

func (m *ListeningPorts) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
Get-NetTCPConnection -State Listen | ForEach-Object {
  $addr = $_.LocalAddress
  $rows += [PSCustomObject]@{
    protocol = 'tcp'
    address_family = if ($addr -match ':') { 'ipv6' } else { 'ipv4' }
    local_address = $addr
    local_port = [int]$_.LocalPort
    owning_pid = [int]$_.OwningProcess
    state = 'listen'
    loopback_only = ($addr -eq '127.0.0.1' -or $addr -eq '::1')
    wildcard_binding = ($addr -eq '0.0.0.0' -or $addr -eq '::')
  }
}
Get-NetUDPEndpoint | ForEach-Object {
  $addr = $_.LocalAddress
  $rows += [PSCustomObject]@{
    protocol = 'udp'
    address_family = if ($addr -match ':') { 'ipv6' } else { 'ipv4' }
    local_address = $addr
    local_port = [int]$_.LocalPort
    owning_pid = [int]$_.OwningProcess
    state = 'listen'
    loopback_only = ($addr -eq '127.0.0.1' -or $addr -eq '::1')
    wildcard_binding = ($addr -eq '0.0.0.0' -or $addr -eq '::')
  }
}
$rows | ConvertTo-Json -Compress -Depth 4
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+out))
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
		proto := asString(row["protocol"])
		addr := asString(row["local_address"])
		port := asInt(row["local_port"])
		pid := asInt(row["owning_pid"])
		row["entity_id"] = entitySocket(proto, addr, port)
		row["entity_type"] = "socket"
		if pid > 0 {
			row["process_entity_id"] = entityProcess(pid)
		} else {
			row["process_entity_id"] = nil
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", row, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

type SecurityProducts struct{}

func (m *SecurityProducts) ID() string          { return "security_products" }
func (m *SecurityProducts) Version() string     { return "1.0.0" }
func (m *SecurityProducts) Platforms() []string { return []string{"windows"} }

func (m *SecurityProducts) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := `
$out = [ordered]@{}
try {
  $mp = Get-MpComputerStatus
  $out.defender = [PSCustomObject]@{
    am_service_enabled = $mp.AMServiceEnabled
    antivirus_enabled = $mp.AntivirusEnabled
    real_time_protection = $mp.RealTimeProtectionEnabled
    antivirus_signature_version = $mp.AntivirusSignatureVersion
    nis_signature_version = $mp.NISSignatureVersion
    quick_scan_age = $mp.QuickScanAge
  }
} catch { $out.defender_error = $_.Exception.Message }
try {
  $out.firewall_profiles = Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress
} catch { $out.firewall_error = $_.Exception.Message }
$out | ConvertTo-Json -Compress -Depth 5
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+out))
		common.Finish(&res, started, "partial")
		return res
	}
	var value map[string]any
	_ = json.Unmarshal([]byte(out), &value)
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, map[string]string{"raw_json": out}))
	common.Finish(&res, started, "success")
	return res
}

type Users struct{}

func (m *Users) ID() string          { return "users" }
func (m *Users) Version() string     { return "1.0.0" }
func (m *Users) Platforms() []string { return []string{"windows"} }

func (m *Users) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := `Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired, Description | ConvertTo-Json -Compress`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+out))
		common.Finish(&res, started, "error")
		return res
	}
	appendJSONRows(&res, m.ID(), out)
	common.Finish(&res, started, "success")
	return res
}

type NetworkInventory struct{}

func (m *NetworkInventory) ID() string          { return "network_inventory" }
func (m *NetworkInventory) Version() string     { return "1.0.0" }
func (m *NetworkInventory) Platforms() []string { return []string{"windows"} }

func (m *NetworkInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())
	script := `Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress, AddressFamily, PrefixLength | ConvertTo-Json -Compress`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+out))
		common.Finish(&res, started, "error")
		return res
	}
	appendJSONRows(&res, m.ID(), out)
	common.Finish(&res, started, "success")
	return res
}

func appendJSONRows(res *schema.ModuleResult, moduleID, out string) {
	if out == "" || out == "null" {
		return
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		var one map[string]any
		if err2 := json.Unmarshal([]byte(out), &one); err2 != nil {
			res.Errors = append(res.Errors, common.Err(moduleID, "collection_error", "json parse: "+err.Error()))
			return
		}
		rows = []map[string]any{one}
	}
	for _, row := range rows {
		res.Evidence = append(res.Evidence, common.Evidence("native", moduleID, "observed", row, nil))
	}
}

func stringify(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
