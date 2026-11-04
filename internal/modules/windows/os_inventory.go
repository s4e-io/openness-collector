package windows

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// Overridable in tests so Run can stay hermetic (no live PowerShell / registry).
var collectOSIdentity = readOSIdentityFromRegistry
var collectOSViaPowerShellFn = collectOSViaPowerShell

func (m *OSInventory) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	raw, source, err := loadWindowsOSIdentity(ctx)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", err.Error()))
		common.Finish(&res, started, "unavailable")
		return res
	}

	value := normalizeWindowsOSIdentity(raw)
	value["go_architecture"] = runtime.GOARCH
	for k, v := range observeWindowsRebootPending() {
		value[k] = v
	}
	rawOut := map[string]string{"source": source}
	if b, err := json.Marshal(raw); err == nil {
		rawOut["raw_json"] = string(b)
	}
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, rawOut))
	if source != "powershell_cim" {
		res.Errors = append(res.Errors, common.Err(m.ID(), "partial", "os_inventory used fallback/merge source="+source))
		common.Finish(&res, started, "partial")
		return res
	}
	common.Finish(&res, started, "success")
	return res
}

func loadWindowsOSIdentity(ctx context.Context) (map[string]any, string, error) {
	var errs []string
	var merged map[string]any
	var sources []string

	mergeLayer := func(raw map[string]any, src string) {
		if raw == nil {
			return
		}
		if merged == nil {
			merged = map[string]any{}
		}
		for k, v := range raw {
			if isEmptyOSValue(merged[k]) && !isEmptyOSValue(v) {
				merged[k] = v
			}
		}
		sources = append(sources, src)
	}

	if raw, err := collectOSViaPowerShellFn(ctx, psOSInventoryCIM); err == nil && hasWindowsOSSignal(raw) {
		mergeLayer(raw, "powershell_cim")
	} else if err != nil {
		errs = append(errs, "powershell_cim: "+err.Error())
	} else {
		errs = append(errs, "powershell_cim: empty identity")
	}

	if !windowsOSIdentityComplete(merged) {
		if raw, err := collectOSViaPowerShellFn(ctx, psOSInventoryRegistryOnly); err == nil && hasWindowsOSSignal(raw) {
			mergeLayer(raw, "powershell_registry")
		} else if err != nil {
			errs = append(errs, "powershell_registry: "+err.Error())
		} else {
			errs = append(errs, "powershell_registry: empty identity")
		}
	}

	if !windowsOSIdentityComplete(merged) {
		if raw, err := collectOSIdentity(); err == nil && hasWindowsOSSignal(raw) {
			mergeLayer(raw, "native_registry")
		} else if err != nil {
			errs = append(errs, "native_registry: "+err.Error())
		} else {
			errs = append(errs, "native_registry: empty identity")
		}
	}

	if !hasWindowsOSSignal(merged) {
		return nil, "", fmt.Errorf("windows os identity unavailable (%s)", strings.Join(errs, "; "))
	}
	return merged, strings.Join(sources, "+"), nil
}

func isEmptyOSValue(v any) bool {
	if v == nil {
		return true
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) == ""
	default:
		return false
	}
}

// windowsOSIdentityComplete requires product_name plus build or display version.
// A CIM row with only version="10.0.x" is not enough — merge the next layer.
func windowsOSIdentityComplete(raw map[string]any) bool {
	if raw == nil {
		return false
	}
	if asString(raw["product_name"]) == "" {
		return false
	}
	return asString(raw["build_number"]) != "" || asString(raw["display_version"]) != ""
}

func collectOSViaPowerShell(ctx context.Context, script string) (map[string]any, error) {
	out, err := runPowerShell(ctx, script)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, out)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("json parse: %w", err)
	}
	return raw, nil
}

func hasWindowsOSSignal(raw map[string]any) bool {
	if raw == nil {
		return false
	}
	return asString(raw["product_name"]) != "" ||
		asString(raw["version"]) != "" ||
		asString(raw["build_number"]) != "" ||
		asString(raw["display_version"]) != ""
}

// normalizeWindowsOSIdentity maps Windows evidence onto the shared Linux-style
// identity fields (distribution_id / version_id / pretty_name) while keeping
// the original Windows keys for downstream Windows modules.
func normalizeWindowsOSIdentity(raw map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range raw {
		out[k] = v
	}

	product := asString(raw["product_name"])
	version := asString(raw["version"]) // e.g. 10.0.20348
	build := asString(raw["build_number"])
	ubr := asString(raw["ubr"])
	display := asString(raw["display_version"])
	releaseID := asString(raw["release_id"])
	installType := asString(raw["installation_type"])
	arch := normalizeWindowsArch(asString(raw["architecture"]))

	// version_id is display_version or release_id only — never invent "10.0"
	// (shared by Win10/11/Server and is not a marketing version id).
	var versionID any
	switch {
	case display != "":
		versionID = display
	case releaseID != "":
		versionID = releaseID
	default:
		versionID = nil
	}

	distVersion := product
	switch {
	case product != "" && display != "":
		distVersion = product + " (" + display + ")"
	case product != "" && build != "":
		distVersion = product + " (build " + build + ")"
	case product != "":
		distVersion = product
	case version != "":
		distVersion = version
	}

	var pretty any
	if product != "" {
		pretty = product
	} else {
		pretty = nil
	}

	out["distribution_id"] = "windows"
	out["distribution_name"] = "Windows"
	out["distribution_version"] = distVersion
	out["version_id"] = versionID
	out["pretty_name"] = pretty
	if installType != "" {
		out["variant"] = installType
	}
	if arch != "" {
		out["architecture"] = arch
	}

	// Convenience full build string when UBR is known.
	if build != "" {
		full := build
		if ubr != "" {
			full = build + "." + ubr
		}
		out["os_build"] = full
	}
	return out
}

func normalizeWindowsArch(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "amd64", "x64", "x86_64":
		return "amd64"
	case "x86", "i386", "i686":
		return "386"
	case "arm64", "aarch64":
		return "arm64"
	case "arm":
		return "arm"
	default:
		return strings.ToLower(strings.TrimSpace(a))
	}
}

// Primary: CIM + registry (rich).
const psOSInventoryCIM = `
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
$dns = [System.Net.Dns]::GetHostEntry('localhost').HostName
if (-not $dns) { $dns = $env:COMPUTERNAME }
$fqdn = if ($cs.PartOfDomain -and $cs.Domain) { "$($env:COMPUTERNAME).$($cs.Domain)" } else { $dns }
$elevated = $false
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $elevated = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
[PSCustomObject]@{
  product_name = $os.Caption
  version = $os.Version
  build_number = $reg.CurrentBuild
  ubr = $reg.UBR
  display_version = $reg.DisplayVersion
  release_id = $reg.ReleaseId
  product_type = $os.ProductType
  installation_type = $reg.InstallationType
  architecture = $env:PROCESSOR_ARCHITECTURE
  hostname = $env:COMPUTERNAME
  fqdn = $fqdn
  machine_id = $guid
  domain_or_workgroup = $cs.Domain
  part_of_domain = [bool]$cs.PartOfDomain
  privilege_level = if ($elevated) { 'admin' } else { 'user' }
  boot_time = $os.LastBootUpTime.ToUniversalTime().ToString('o')
  system_language = (Get-Culture).Name
  timezone = (Get-TimeZone).Id
  powershell_version = $PSVersionTable.PSVersion.ToString()
} | ConvertTo-Json -Compress
`

// Fallback when CIM/WMI is blocked but PowerShell registry access still works.
const psOSInventoryRegistryOnly = `
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -ErrorAction SilentlyContinue).MachineGuid
$elevated = $false
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $elevated = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}
$product = $reg.ProductName
if (-not $product) { $product = $reg.EditionID }
[PSCustomObject]@{
  product_name = $product
  # CurrentVersion (e.g. "6.3") is not a real OS version on Win10/11/Server; leave null.
  # build_number / display_version / release_id carry the observed identity.
  version = $null
  build_number = $reg.CurrentBuild
  ubr = $reg.UBR
  display_version = $reg.DisplayVersion
  release_id = $reg.ReleaseId
  installation_type = $reg.InstallationType
  architecture = $env:PROCESSOR_ARCHITECTURE
  hostname = $env:COMPUTERNAME
  fqdn = $env:COMPUTERNAME
  machine_id = $guid
  privilege_level = if ($elevated) { 'admin' } else { 'user' }
  powershell_version = $PSVersionTable.PSVersion.ToString()
} | ConvertTo-Json -Compress
`
