package windows

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// securityConfigurationScript returns the PowerShell that reads the registry
// list from specPath. An empty specPath reads no registry values (every listed
// value is then reported as not_reported by normalizeRegistryEntries).
func securityConfigurationScript(specPath string) string {
	return strings.Replace(securityConfigurationScriptTemplate, registrySpecPathPlaceholder, psSingleQuote(specPath), 1)
}

// writeRegistrySpecFile writes specs as JSON to a temp file for the script.
func writeRegistrySpecFile(specs []RegistryValueSpec) (string, error) {
	f, err := os.CreateTemp("", "openness-registry-*.json")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.WriteString(registrySpecJSON(specs)); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// SecurityConfiguration collects effective Windows security settings with source/precedence.
type SecurityConfiguration struct {
	// ExtraRegistry holds values requested at run time (collect
	// --registry-values), already validated by ParseRegistryValuesArg. They
	// are merged into the built-in table and emitted in the same registry list.
	ExtraRegistry []RegistryValueSpec
}

func (m *SecurityConfiguration) ID() string          { return "security_configuration" }
func (m *SecurityConfiguration) Version() string     { return "1.4.0" }
func (m *SecurityConfiguration) Platforms() []string { return []string{"windows"} }

func (m *SecurityConfiguration) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	specs := mergeRegistrySpecs(securityRegistrySpecs, m.ExtraRegistry)
	specPath, specErr := writeRegistrySpecFile(specs)
	if specErr != nil {
		specPath = ""
		res.Errors = append(res.Errors, common.Err(m.ID(), "registry_spec_error", specErr.Error()))
	} else {
		defer os.Remove(specPath)
	}
	script := securityConfigurationScript(specPath)
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+truncate(out, 400)))
		common.Finish(&res, started, "error")
		return res
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(out), &value); err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	value["registry"] = normalizeRegistryEntries(value["registry"], specs)
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", value, nil))
	status := "success"
	if len(res.Errors) > 0 {
		status = "partial"
	}
	common.Finish(&res, started, status)
	return res
}

const securityConfigurationScriptTemplate = `
$ErrorActionPreference = 'SilentlyContinue'
function Setting($name, $configured, $effective, $runtime, $source, $scope, $default, $gpo, $mdm, $conflict, $reboot) {
  [PSCustomObject]@{
    name = $name
    configured_value = $configured
    effective_value = $effective
    runtime_value = $runtime
    source = $source
    scope = $scope
    default_value = $default
    gpo_influence = $gpo
    mdm_influence = $mdm
    conflict = $conflict
    reboot_required = $reboot
  }
}

# --- Read-only registry access (.NET; the PS registry provider treats '/' in
# key names such as 'RC4 128/128' as a path separator). Never writes. ---
$hklm = $null
try {
  if ([Environment]::Is64BitOperatingSystem) {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
  } else {
    $hklm = [Microsoft.Win32.Registry]::LocalMachine
  }
} catch { $hklm = $null }
function Get-RegErrorCode($ex) {
  $e = $ex
  while ($null -ne $e.InnerException) { $e = $e.InnerException }
  if ($e -is [System.Security.SecurityException] -or $e -is [System.UnauthorizedAccessException]) { return 'access_denied' }
  return ('read_failed: ' + $e.GetType().Name)
}
function New-RegEntry($key, $name, $pattern) {
  $o = [ordered]@{ key = $key; name = $name; hive = 'HKLM'; present = $false; type = $null; value = $null }
  if ($pattern) { $o.pattern = $pattern }
  return $o
}
function Read-RegValue($key, $name, $presenceOnly, $pattern) {
  $o = New-RegEntry $key $name $pattern
  if ($null -eq $hklm) { $o.error = 'hive_unavailable'; return [PSCustomObject]$o }
  $k = $null
  try {
    $k = $hklm.OpenSubKey($key, $false)
    if ($null -ne $k) {
      $hit = $null
      foreach ($n in @($k.GetValueNames())) { if ($n -eq $name) { $hit = $n; break } }
      if ($null -ne $hit) {
        $kind = $k.GetValueKind($hit)
        $o.present = $true
        $o.type = [string]$kind
        # Presence-only values (secrets) are never read.
        if (-not $presenceOnly) {
          $raw = $k.GetValue($hit, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
          switch ([string]$kind) {
            'DWord' { $o.value = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$raw), 0) }
            'QWord' { $o.value = [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$raw), 0) }
            'MultiString' { $o.value = [string[]]$raw }
            'Binary' { $o.value = ([BitConverter]::ToString([byte[]]$raw) -replace '-', '') }
            default { if ($null -ne $raw) { $o.value = [string]$raw } }
          }
        }
      }
    }
  } catch {
    $o.present = $false
    $o.type = $null
    $o.value = $null
    $o.error = Get-RegErrorCode $_.Exception
  } finally {
    if ($null -ne $k) { $k.Close() }
  }
  return [PSCustomObject]$o
}

# --- Defender ---
$defender = [ordered]@{ adapter = 'microsoft_defender'; status = 'unavailable'; settings = @() }
try {
  $mp = Get-MpComputerStatus -EA Stop
  $prefs = Get-MpPreference -EA SilentlyContinue
  $defender.status = 'observed'
  $defender.settings += Setting 'antivirus_enabled' $null $mp.AntivirusEnabled $mp.AntivirusEnabled 'Get-MpComputerStatus' 'machine' $null $null $null $false $null
  $defender.settings += Setting 'real_time_protection' $prefs.DisableRealtimeMonitoring $mp.RealTimeProtectionEnabled $mp.RealTimeProtectionEnabled 'Get-MpComputerStatus/Get-MpPreference' 'machine' $false $null $null $false $null
  $defender.settings += Setting 'am_service_enabled' $null $mp.AMServiceEnabled $mp.AMServiceEnabled 'Get-MpComputerStatus' 'machine' $null $null $null $false $null
  $defender.settings += Setting 'antivirus_signature_version' $null $mp.AntivirusSignatureVersion $mp.AntivirusSignatureVersion 'Get-MpComputerStatus' 'machine' $null $null $null $false $null
  $defender.settings += Setting 'nis_enabled' $null $mp.NISEnabled $mp.NISEnabled 'Get-MpComputerStatus' 'machine' $null $null $null $false $null
  $defender.settings += Setting 'behavior_monitor' $null $mp.BehaviorMonitorEnabled $mp.BehaviorMonitorEnabled 'Get-MpComputerStatus' 'machine' $null $null $null $false $null
  $defender.signature_last_updated = $mp.AntivirusSignatureLastUpdated
  $defender.quick_scan_age_days = $mp.QuickScanAge
} catch {
  $defender.status = 'unavailable'
  $defender.message = $_.Exception.Message
}

# --- Firewall ---
$firewall = [ordered]@{ adapter = 'windows_firewall'; status = 'unavailable'; profiles = @(); settings = @() }
try {
  $profiles = Get-NetFirewallProfile -EA Stop
  $firewall.status = 'observed'
  foreach ($p in $profiles) {
    $pname = [string]$p.Name
    $enabled = [bool]$p.Enabled
    $firewall.profiles += [PSCustomObject]@{
      name = $pname
      enabled = $enabled
      default_inbound = [string]$p.DefaultInboundAction
      default_outbound = [string]$p.DefaultOutboundAction
      source = 'Get-NetFirewallProfile'
      scope = 'machine'
    }
    $firewall.settings += Setting ("profile_${pname}_enabled") $enabled $enabled $enabled 'Get-NetFirewallProfile' 'machine' $null $null $null $false $null
    $firewall.settings += Setting ("profile_${pname}_default_inbound") ([string]$p.DefaultInboundAction) ([string]$p.DefaultInboundAction) ([string]$p.DefaultInboundAction) 'Get-NetFirewallProfile' 'machine' $null $null $null $false $null
  }
} catch {
  $firewall.status = 'unavailable'
  $firewall.message = $_.Exception.Message
}

# --- SMB ---
$smb = [ordered]@{ adapter = 'smb'; status = 'observed'; settings = @() }
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -EA SilentlyContinue
if ($smb1) {
  $smb.settings += Setting 'smb1_feature' $smb1.State ([string]$smb1.State) ([string]$smb1.State) 'Get-WindowsOptionalFeature' 'machine' 'Disabled' $null $null $false $null
} else {
  $smb.settings += Setting 'smb1_feature' $null $null $null 'Get-WindowsOptionalFeature' 'machine' $null $null $null $false $null
  $smb.settings[-1] | Add-Member -NotePropertyName note -NotePropertyValue 'feature_query_unavailable' -Force
}
$smbServer = Get-SmbServerConfiguration -EA SilentlyContinue
if ($smbServer) {
  $smb.settings += Setting 'encrypt_data' $smbServer.EncryptData $smbServer.EncryptData $smbServer.EncryptData 'Get-SmbServerConfiguration' 'machine' $false $null $null $false $null
  $smb.settings += Setting 'enable_smb1_protocol' $smbServer.EnableSMB1Protocol $smbServer.EnableSMB1Protocol $smbServer.EnableSMB1Protocol 'Get-SmbServerConfiguration' 'machine' $false $null $null $false $null
  $smb.settings += Setting 'enable_smb2_protocol' $smbServer.EnableSMB2Protocol $smbServer.EnableSMB2Protocol $smbServer.EnableSMB2Protocol 'Get-SmbServerConfiguration' 'machine' $true $null $null $false $null
  $smb.settings += Setting 'reject_unencrypted_access' $smbServer.RejectUnencryptedAccess $smbServer.RejectUnencryptedAccess $smbServer.RejectUnencryptedAccess 'Get-SmbServerConfiguration' 'machine' $null $null $null $false $null
} else {
  # Windows 7 / 2008 R2 have no SmbShare module. Record the LanmanServer values
  # as read; an absent value stays null (no OS default is assumed here).
  $smb.status = 'partial'
  $smb.message = 'Get-SmbServerConfiguration unavailable; server settings read from LanmanServer registry'
  $lanmanKey = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
  foreach ($fb in @(
    [PSCustomObject]@{ setting = 'require_security_signature_server'; value_name = 'RequireSecuritySignature' },
    [PSCustomObject]@{ setting = 'enable_security_signature_server'; value_name = 'EnableSecuritySignature' },
    [PSCustomObject]@{ setting = 'enable_smb1_protocol'; value_name = 'SMB1' }
  )) {
    $r = Read-RegValue $lanmanKey $fb.value_name $false $null
    $smb.settings += Setting $fb.setting $r.value $null $null 'registry_fallback' 'machine' $null $null $null $false $null
    $smb.settings[-1] | Add-Member -NotePropertyName registry_path -NotePropertyValue ('HKLM\' + $lanmanKey + '\' + $fb.value_name) -Force
    $smb.settings[-1] | Add-Member -NotePropertyName registry_present -NotePropertyValue ([bool]$r.present) -Force
    if ($r.error) {
      $smb.settings[-1] | Add-Member -NotePropertyName error -NotePropertyValue $r.error -Force
    }
  }
}
$smbClient = Get-SmbClientConfiguration -EA SilentlyContinue
if ($smbClient) {
  $smb.settings += Setting 'require_security_signature_client' $smbClient.RequireSecuritySignature $smbClient.RequireSecuritySignature $smbClient.RequireSecuritySignature 'Get-SmbClientConfiguration' 'machine' $null $null $null $false $null
}

# --- RDP ---
$rdp = [ordered]@{ adapter = 'rdp'; status = 'observed'; settings = @() }
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -EA SilentlyContinue
$rdpEnabledConfigured = $null
if ($null -ne $ts.fDenyTSConnections) {
  $rdpEnabledConfigured = -not [bool]$ts.fDenyTSConnections
  $rdp.settings += Setting 'rdp_enabled' $rdpEnabledConfigured $rdpEnabledConfigured $rdpEnabledConfigured 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections' 'machine' $false $null $null $false $null
}
$nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA SilentlyContinue
if ($null -ne $nla.UserAuthentication) {
  $rdp.settings += Setting 'network_level_authentication' $nla.UserAuthentication $nla.UserAuthentication $nla.UserAuthentication 'HKLM\...\RDP-Tcp\UserAuthentication' 'machine' 1 $null $null $false $null
}
if ($null -ne $nla.MinEncryptionLevel) {
  $rdp.settings += Setting 'min_encryption_level' $nla.MinEncryptionLevel $nla.MinEncryptionLevel $nla.MinEncryptionLevel 'HKLM\...\RDP-Tcp\MinEncryptionLevel' 'machine' $null $null $null $false $null
}
$rdpSvc = Get-Service TermService -EA SilentlyContinue
if ($rdpSvc) {
  $rdp.settings += Setting 'termservice_state' $null $rdpSvc.Status ([string]$rdpSvc.Status) 'Get-Service TermService' 'machine' $null $null $null $false $null
}
# GPO hint (do not claim override without evidence)
$gpoRdp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -EA SilentlyContinue
if ($gpoRdp) {
  $rdp.gpo_present = $true
  if ($null -ne $gpoRdp.fDenyTSConnections) {
    $rdp.settings += Setting 'rdp_enabled_policy' (-not [bool]$gpoRdp.fDenyTSConnections) (-not [bool]$gpoRdp.fDenyTSConnections) $null 'HKLM\SOFTWARE\Policies\...\Terminal Services' 'machine' $null $true $null $true $null
  }
}

# --- TLS / Schannel ---
# Observation only: never invent OS defaults (TLS 1.3 / TLS 1.0|1.1 policy vary by build).
# Resolver derives effective enablement from build + these registry observations.
$tls = [ordered]@{ adapter = 'tls_schannel'; status = 'observed'; protocols = @(); settings = @(); cipher_suites_policy = $null }
$protoRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
foreach ($proto in @('TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3','SSL 2.0','SSL 3.0')) {
  foreach ($side in @('Server','Client')) {
    $path = Join-Path (Join-Path $protoRoot $proto) $side
    $settingName = (($proto -replace '\s+','_') + '_' + $side + '_enabled').ToLower()
    $keyPresent = $false
    $enabledRegistry = $null
    $dbd = $null
    $source = 'absent'
    if (Test-Path $path) {
      $keyPresent = $true
      $source = $path.Replace('HKLM:\','HKLM\')
      $p = Get-ItemProperty $path -EA SilentlyContinue
      if ($null -ne $p.PSObject.Properties['Enabled']) {
        $enabledRegistry = ([int]$p.Enabled -ne 0)
      }
      if ($null -ne $p.PSObject.Properties['DisabledByDefault']) {
        $dbd = ([int]$p.DisabledByDefault -ne 0)
      }
    }
    $tls.protocols += [PSCustomObject]@{
      protocol = $proto
      side = $side
      enabled_registry = $enabledRegistry
      disabled_by_default = $dbd
      key_present = [bool]$keyPresent
      source = $source
      scope = 'machine'
      note = 'registry_observation_only'
    }
    $tls.settings += Setting $settingName $enabledRegistry $null $null $source 'machine' $null $null $null $false $null
    $tls.settings[-1] | Add-Member -NotePropertyName note -NotePropertyValue 'registry_observation_only' -Force
  }
}
$cipherPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -EA SilentlyContinue
if ($cipherPolicy -and $cipherPolicy.Functions) {
  $tls.cipher_suites_policy = [PSCustomObject]@{
    present = $true
    source = 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
    functions = $cipherPolicy.Functions
    gpo_influence = $true
  }
} else {
  $tls.cipher_suites_policy = [PSCustomObject]@{ present = $false; source = 'default'; gpo_influence = $false }
}
# Effective cipher suite surface (Schannel order). Policy Functions alone is not enough when present=false.
# When the cmdlet is missing (2012 R2 and older) or fails, cipher_suites and
# cipher_suites_count stay null so "not collected" never reads as "no suites".
$tls.cipher_suites = $null
$tls.cipher_suites_source = 'unavailable'
$tls.cipher_suites_count = $null
$tls.cipher_suites_has_3des = $null
if (-not (Get-Command Get-TlsCipherSuite -EA SilentlyContinue)) {
  $tls.cipher_suites_error = 'Get-TlsCipherSuite not available on this Windows version'
} else {
  try {
    # Get-TlsCipherSuite returns List[TlsCipherSuite]. Pipeline/ForEach-Object and @() can
    # treat the whole list as one object (Name/Cipher become Object[]). Index explicitly.
    $suiteList = Get-TlsCipherSuite -EA Stop
    $suites = @()
    for ($i = 0; $i -lt $suiteList.Count; $i++) {
      $s = $suiteList[$i]
      if ($null -eq $s) { continue }
      $suites += [PSCustomObject]@{
        name = [string]$s.Name
        cipher = [string]$s.Cipher
        cipher_strength = $s.CipherLength
        exchange = [string]$s.Exchange
        hash = [string]$s.Hash
      }
    }
    $tls.cipher_suites = $suites
    $tls.cipher_suites_source = 'Get-TlsCipherSuite'
    $tls.cipher_suites_count = @($suites).Count
    $tls.cipher_suites_has_3des = [bool](@($suites | Where-Object { $_.name -match '3DES|TripleDES' }).Count -gt 0)
  } catch {
    $tls.cipher_suites = $null
    $tls.cipher_suites_source = 'unavailable'
    $tls.cipher_suites_error = $_.Exception.Message
    $tls.cipher_suites_count = $null
    $tls.cipher_suites_has_3des = $null
  }
}

# --- WinRM (light) ---
$winrm = [ordered]@{ adapter = 'winrm'; status = 'observed'; settings = @() }
$winrmSvc = Get-Service WinRM -EA SilentlyContinue
if ($winrmSvc) {
  $winrm.settings += Setting 'winrm_service' $null ([string]$winrmSvc.Status) ([string]$winrmSvc.Status) 'Get-Service WinRM' 'machine' $null $null $null $false $null
}
try {
  $listeners = Get-ChildItem 'WSMan:\Localhost\Listener' -EA SilentlyContinue
  $winrm.listener_count = @($listeners).Count
} catch { $winrm.listener_count = $null }

# --- curl inbox binaries (file version / size / mtime only; not a display_version substitute) ---
$curl_file_meta = @()
foreach ($cp in @(
  (Join-Path $env:SystemRoot 'System32\curl.exe'),
  (Join-Path $env:SystemRoot 'SysWOW64\curl.exe')
)) {
  if (-not (Test-Path $cp)) {
    $curl_file_meta += [PSCustomObject]@{ path = $cp; present = $false }
    continue
  }
  $item = Get-Item $cp
  $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($cp)
  $curl_file_meta += [PSCustomObject]@{
    path = $cp
    present = $true
    file_version = $vi.FileVersion
    length = [int64]$item.Length
    last_write_time_utc = $item.LastWriteTimeUtc.ToString('o')
  }
}

# SMB server signing (server-side setting; keep client setting separate above)
if ($smbServer) {
  $smb.settings += Setting 'require_security_signature_server' $smbServer.RequireSecuritySignature $smbServer.RequireSecuritySignature $smbServer.RequireSecuritySignature 'Get-SmbServerConfiguration' 'machine' $null $null $null $false $null
  $smb.settings += Setting 'enable_security_signature_server' $smbServer.EnableSecuritySignature $smbServer.EnableSecuritySignature $smbServer.EnableSecuritySignature 'Get-SmbServerConfiguration' 'machine' $null $null $null $false $null
  $smb.require_security_signature_server = [bool]$smbServer.RequireSecuritySignature
  $smb.enable_security_signature_server = [bool]$smbServer.EnableSecuritySignature
}

# --- WinVerifyTrust EnableCertPaddingCheck (registry observation only) ---
function Get-CertPaddingCheck($regPath) {
  # null = key/value not observed; numeric/string = registry value as read.
  if (-not (Test-Path $regPath)) { return $null }
  try {
    $v = (Get-ItemProperty $regPath -Name EnableCertPaddingCheck -EA Stop).EnableCertPaddingCheck
    return $v
  } catch {
    return $null
  }
}
$wintrust_enable_cert_padding_check_native = Get-CertPaddingCheck 'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config'
$wintrust_enable_cert_padding_check_wow64 = Get-CertPaddingCheck 'HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config'

# --- Registry values (list supplied by the collector, see security_registry.go) ---
$registrySpec = @()
$registrySpecPath = __OPENNESS_REGISTRY_SPEC_PATH__
if ($registrySpecPath) {
  try {
    $registrySpec = [IO.File]::ReadAllText($registrySpecPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
  } catch {
    $registrySpec = @()
  }
}
$registry = @()
foreach ($rs in @($registrySpec)) {
  if ($null -eq $rs -or -not $rs.key) { continue }
  $presenceOnly = [bool]$rs.presence_only
  if ($rs.key.EndsWith('\*')) {
    $parent = $rs.key.Substring(0, $rs.key.Length - 2)
    $subs = @()
    $subErr = $null
    if ($null -eq $hklm) {
      $subErr = 'hive_unavailable'
    } else {
      $pk = $null
      try {
        $pk = $hklm.OpenSubKey($parent, $false)
        if ($null -ne $pk) { $subs = @($pk.GetSubKeyNames()) }
      } catch {
        $subErr = Get-RegErrorCode $_.Exception
      } finally {
        if ($null -ne $pk) { $pk.Close() }
      }
    }
    if ($subErr -or $subs.Count -eq 0) {
      $o = New-RegEntry $rs.key $rs.name $rs.key
      if ($subErr) { $o.error = $subErr }
      $registry += [PSCustomObject]$o
    } else {
      foreach ($sub in $subs) {
        $registry += Read-RegValue ($parent + '\' + $sub) $rs.name $presenceOnly $rs.key
      }
    }
  } else {
    $registry += Read-RegValue $rs.key $rs.name $presenceOnly $null
  }
}

[PSCustomObject]@{
  entity_type = 'security_configuration'
  entity_id = 'win:security_configuration'
  microsoft_defender = $defender
  windows_firewall = $firewall
  smb = $smb
  rdp = $rdp
  tls_schannel = $tls
  winrm = $winrm
  curl_file_meta = $curl_file_meta
  wintrust_enable_cert_padding_check_native = $wintrust_enable_cert_padding_check_native
  wintrust_enable_cert_padding_check_wow64 = $wintrust_enable_cert_padding_check_wow64
  registry = $registry
} | ConvertTo-Json -Compress -Depth 8
`
