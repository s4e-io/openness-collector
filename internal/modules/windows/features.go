package windows

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// featuresCmdletTimeout bounds the DISM-backed cmdlets. Get-WindowsOptionalFeature
// can block for minutes while TrustedInstaller/CBS is busy; the module should
// report that quickly instead of burning the whole per-module budget.
const featuresCmdletTimeout = 45 * time.Second

// WindowsFeatures collects server roles and optional features.
//
// Two sources, cheapest first:
//  1. Server Manager component cache in the registry (native read, milliseconds).
//     Covers server roles/features as Server Manager last recorded them.
//  2. Get-WindowsOptionalFeature / Get-WindowsFeature (DISM), bounded by
//     featuresCmdletTimeout. Covers optional features on client and server.
//
// The cache rows are tagged source=servermanager_component_cache so a reader
// knows they are a cache, not a live DISM query.
type WindowsFeatures struct{}

func (m *WindowsFeatures) ID() string          { return "windows_features" }
func (m *WindowsFeatures) Version() string     { return "1.1.0" }
func (m *WindowsFeatures) Platforms() []string { return []string{"windows"} }

// Overridable in tests.
var (
	readServerComponentCacheFn = readServerComponentCache
	runFeaturesCmdletFn        = runFeaturesCmdlet
)

// serverComponent is one row from the Server Manager component cache.
type serverComponent struct {
	Name         string
	InstallState int64 // raw DWORD; 1 = installed per Server Manager
	HasState     bool
}

func (m *WindowsFeatures) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	// 1. Registry fast path (native).
	cached, cacheErr := readServerComponentCacheFn()
	cacheRows := 0
	for _, c := range cached {
		state, raw := mapComponentCacheState(c)
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", map[string]any{
			"entity_type":        "windows_feature",
			"entity_id":          "feature:role:" + c.Name,
			"feature_name":       c.Name,
			"display_name":       c.Name,
			"state":              state,
			"install_state_raw":  raw,
			"feature_type":       "server_role",
			"parent_feature":     nil,
			"payload_removed":    false,
			"restart_required":   nil,
			"source":             "servermanager_component_cache",
			"package_identities": []string{},
		}, nil))
		cacheRows++
	}
	if cacheErr != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "cache_unavailable", "server component cache: "+cacheErr.Error()))
	}

	// 2. DISM cmdlets with their own deadline.
	cctx, cancel := context.WithTimeout(ctx, featuresCmdletTimeout)
	defer cancel()
	cmdStarted := time.Now()
	rows, err := runFeaturesCmdletFn(cctx)
	cmdMs := time.Since(cmdStarted).Milliseconds()
	switch {
	case err != nil && errors.Is(cctx.Err(), context.DeadlineExceeded):
		res.Errors = append(res.Errors, common.Err(m.ID(), "FEATURE_API_TIMEOUT",
			"Get-WindowsOptionalFeature/Get-WindowsFeature exceeded "+featuresCmdletTimeout.String()+" (DISM/CBS busy); optional features not enumerated"))
	case err != nil:
		res.Errors = append(res.Errors, common.Err(m.ID(), "FEATURE_API_UNAVAILABLE", err.Error()))
	default:
		seen := map[string]bool{}
		for _, ev := range res.Evidence {
			if v, ok := ev.Value.(map[string]any); ok {
				seen[asString(v["entity_id"])] = true
			}
		}
		for _, row := range rows {
			id := asString(row["entity_id"])
			if seen[id] {
				// Live DISM answer wins over the cache row for the same role.
				for i := range res.Evidence {
					if v, ok := res.Evidence[i].Value.(map[string]any); ok && asString(v["entity_id"]) == id {
						row["cache_install_state_raw"] = v["install_state_raw"]
						res.Evidence[i].Value = row
					}
				}
				continue
			}
			res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", row, nil))
		}
	}

	res.Evidence = append([]schema.EvidenceRecord{common.Evidence("native", m.ID(), "observed", map[string]any{
		"entity_type":            "windows_features_context",
		"entity_id":              "feature:context",
		"cache_rows":             cacheRows,
		"cmdlet_rows":            len(rows),
		"cmdlet_duration_ms":     cmdMs,
		"cmdlet_timeout_seconds": int(featuresCmdletTimeout.Seconds()),
		"cmdlet_status":          cmdletStatus(err, cctx),
	}, nil)}, res.Evidence...)

	switch {
	case err == nil:
		common.Finish(&res, started, "success")
	case cacheRows > 0:
		common.Finish(&res, started, "partial")
	default:
		common.Finish(&res, started, "unavailable")
	}
	return res
}

func cmdletStatus(err error, ctx context.Context) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "timeout"
	default:
		return "error"
	}
}

// mapComponentCacheState maps Server Manager InstallState to the module's
// state vocabulary. Only 1 (installed) and 0 (available) are asserted; any
// other raw value stays "unknown" with the raw number beside it.
func mapComponentCacheState(c serverComponent) (string, any) {
	if !c.HasState {
		return "unknown", nil
	}
	switch c.InstallState {
	case 1:
		return "enabled", c.InstallState
	case 0:
		return "disabled", c.InstallState
	default:
		return "unknown", c.InstallState
	}
}

// runFeaturesCmdlet runs the DISM-backed cmdlets and returns feature rows.
func runFeaturesCmdlet(ctx context.Context) ([]map[string]any, error) {
	out, err := runPowerShell(ctx, featuresScript)
	if err != nil {
		return nil, errors.New(err.Error() + ": " + truncate(out, 300))
	}
	var maybeErr map[string]any
	if json.Unmarshal([]byte(out), &maybeErr) == nil && maybeErr["error"] != nil {
		return nil, errors.New(asString(maybeErr["code"]) + ": " + asString(maybeErr["error"]))
	}
	return decodeJSONRows(out)
}

const featuresScript = `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()
function Map-State($s) {
  switch ([string]$s) {
    'Enabled' { 'enabled' }
    'Disabled' { 'disabled' }
    'DisablePending' { 'uninstall_pending' }
    'EnablePending' { 'install_pending' }
    'DisabledWithPayloadRemoved' { 'payload_removed' }
    'Installed' { 'enabled' }
    'Available' { 'disabled' }
    'Removed' { 'not_present' }
    'InstallPending' { 'install_pending' }
    'UninstallPending' { 'uninstall_pending' }
    default { 'unknown' }
  }
}
try {
  Get-WindowsOptionalFeature -Online | ForEach-Object {
    $rows += [PSCustomObject]@{
      entity_type = 'windows_feature'
      entity_id = ('feature:' + $_.FeatureName)
      feature_name = $_.FeatureName
      display_name = $_.FeatureName
      state = Map-State $_.State
      feature_type = 'optional_feature'
      parent_feature = $null
      payload_removed = ([string]$_.State -eq 'DisabledWithPayloadRemoved')
      restart_required = $null
      source = 'Get-WindowsOptionalFeature'
      package_identities = @()
    }
  }
} catch {
  @{ error = $_.Exception.Message; code = 'FEATURE_API_UNAVAILABLE' } | ConvertTo-Json -Compress
  exit 0
}
# Server Manager roles if available
try {
  if (Get-Command Get-WindowsFeature -EA SilentlyContinue) {
    Get-WindowsFeature | Where-Object { $_.Installed -or $_.InstallState } | ForEach-Object {
      $st = if ($_.InstallState) { Map-State $_.InstallState } elseif ($_.Installed) { 'enabled' } else { 'not_present' }
      $rows += [PSCustomObject]@{
        entity_type='windows_feature'; entity_id=('feature:role:' + $_.Name)
        feature_name=$_.Name; display_name=$_.DisplayName
        state=$st; feature_type='server_role'
        parent_feature=$_.Parent; payload_removed=$false
        restart_required=$null; source='Get-WindowsFeature'; package_identities=@()
      }
    }
  }
} catch {}
$rows | ConvertTo-Json -Compress -Depth 4
`
