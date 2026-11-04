package windows

import (
	"context"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// Applications collects multi-source Windows application inventory (not Win32_Product crawl).
func (m *Applications) Version() string { return "1.4.0" }

func (m *Applications) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	script := `
$ErrorActionPreference = 'SilentlyContinue'
$rows = @()

function Add-App($obj) {
  if (-not $obj.product_name) { return }
  $script:rows += $obj
}

# Machine uninstall (64 + 32)
foreach ($p in @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)) {
  Get-ItemProperty $p | Where-Object { $_.DisplayName } | ForEach-Object {
    $arch = if ($p -like '*WOW6432Node*') { 'x86' } else { 'x64' }
    $versions = @()
    if ($_.DisplayVersion) {
      $versions += [PSCustomObject]@{ source='uninstall_registry'; value=$_.DisplayVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') }
    }
    Add-App ([PSCustomObject]@{
      entity_type = 'application'
      entity_id = ('app:uninstall:' + $_.PSChildName)
      product_name = $_.DisplayName
      normalized_name = $_.DisplayName.ToLowerInvariant()
      display_version = $_.DisplayVersion
      publisher = $_.Publisher
      install_scope = 'machine'
      architecture = $arch
      install_location = $_.InstallLocation
      install_date = $_.InstallDate
      uninstall_string = $_.UninstallString
      product_code = if ($_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { $_.PSChildName } else { $null }
      key = $_.PSChildName
      view = if ($arch -eq 'x86') { 'HKLM32' } else { 'HKLM64' }
      display_icon = $_.DisplayIcon
      registry_paths = @($_.PSPath)
      source_type = 'uninstall_registry'
      version_evidence = $versions
      adapter = $null
    })
  }
}

# Per-user uninstall
Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -EA SilentlyContinue | ForEach-Object {
  $props = Get-ItemProperty $_.PSPath
  if (-not $props.DisplayName) { return }
  $versions = @()
  if ($props.DisplayVersion) { $versions += [PSCustomObject]@{ source='uninstall_registry_user'; value=$props.DisplayVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id=('app:uninstall_user:' + $_.PSChildName)
    product_name=$props.DisplayName; normalized_name=$props.DisplayName.ToLowerInvariant()
    display_version=$props.DisplayVersion; publisher=$props.Publisher
    install_scope='user'; architecture='unknown'; install_location=$props.InstallLocation
    key=$_.PSChildName; view='HKCU'; display_icon=$props.DisplayIcon
    product_code= if ($_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { $_.PSChildName } else { $null }
    registry_paths=@($props.PSPath); source_type='uninstall_registry_user'; version_evidence=$versions
  })
}

# AppX / MSIX (no mutation)
try {
  Get-AppxPackage -EA SilentlyContinue | ForEach-Object {
    $versions = @([PSCustomObject]@{ source='appx_manifest'; value=$_.Version.ToString(); observed_at=(Get-Date).ToUniversalTime().ToString('o') })
    Add-App ([PSCustomObject]@{
      entity_type='application'; entity_id=('app:appx:' + $_.PackageFullName)
      product_name=$_.Name; normalized_name=$_.Name.ToLowerInvariant()
      display_version=$_.Version.ToString(); publisher=$_.Publisher
      install_scope='machine'; architecture=$_.Architecture.ToString()
      install_location=$_.InstallLocation
      package_family_name=$_.PackageFamilyName
      package_full_name=$_.PackageFullName
      source_type='appx'; version_evidence=$versions
    })
  }
} catch {}

# MSI product codes via registry Installer\Products (avoid Win32_Product)
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties' -EA SilentlyContinue | ForEach-Object {
  $ip = Get-ItemProperty $_.PSPath
  if (-not $ip.DisplayName) { return }
  $versions = @()
  if ($ip.DisplayVersion) { $versions += [PSCustomObject]@{ source='msi_installproperties'; value=$ip.DisplayVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id=('app:msi:' + $_.PSParentPath.Split('\')[-1])
    product_name=$ip.DisplayName; normalized_name=$ip.DisplayName.ToLowerInvariant()
    display_version=$ip.DisplayVersion; publisher=$ip.Publisher
    install_scope='machine'; install_location=$ip.InstallLocation
    source_type='msi_userdata'; version_evidence=$versions
    registry_paths=@($ip.PSPath)
  })
}

# Product adapters (evidence-led, allowlisted registry/paths)
# Edge
$edge = 'HKLM:\SOFTWARE\Microsoft\Edge\BLBeacon'
if (Test-Path $edge) {
  $e = Get-ItemProperty $edge
  $ver = $e.version
  $versions = @([PSCustomObject]@{ source='edge_blbeacon'; value=$ver; observed_at=(Get-Date).ToUniversalTime().ToString('o') })
  $pe = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
  if (Test-Path $pe) {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($pe)
    if ($vi.ProductVersion) { $versions += [PSCustomObject]@{ source='pe_file_version'; value=$vi.ProductVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id='app:adapter:edge'
    product_name='Microsoft Edge'; normalized_name='microsoft edge'
    display_version=$ver; publisher='Microsoft Corporation'
    install_scope='machine'; install_location='C:\Program Files (x86)\Microsoft\Edge\Application'
    source_type='product_adapter'; adapter='edge'; version_evidence=$versions
  })
}

# .NET Framework release key (do not rewrite ARP/uninstall DisplayVersion rows)
$ndp = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
if (Test-Path $ndp) {
  $n = Get-ItemProperty $ndp
  $versions = @([PSCustomObject]@{ source='ndp_release'; value=[string]$n.Release; observed_at=(Get-Date).ToUniversalTime().ToString('o') })
  if ($n.Version) { $versions += [PSCustomObject]@{ source='ndp_version'; value=$n.Version; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id='app:adapter:netfx4'
    product_name='Microsoft .NET Framework 4'
    normalized_name='microsoft .net framework 4'
    display_version=$n.Version; publisher='Microsoft Corporation'
    install_scope='machine'; source_type='product_adapter'; adapter='netfx'
    version_evidence=$versions
  })
  if ($null -ne $n.Release) {
    Add-App ([PSCustomObject]@{
      entity_type='application'; entity_id='app:ndp_release:v4full'
      product_name='.NET Framework NDP v4 Full release key'
      normalized_name='.net framework ndp v4 full release key'
      display_version=$n.Version
      release_dword=[int]$n.Release
      publisher='Microsoft Corporation'
      install_scope='machine'
      source_type='ndp_release'
      path=$null
      registry_path='HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
      ndp_version=$n.Version
      version_evidence=$versions
    })
  }
}

# .NET Framework64 runtime DLL file versions (MSRC file-version scoring)
$fxDir = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319'
$fxDlls = @(
  @{ file='System.dll'; product='.NET Framework 4 System.dll' },
  @{ file='clr.dll'; product='.NET Framework 4 clr.dll' },
  @{ file='mscorlib.dll'; product='.NET Framework 4 mscorlib.dll' },
  @{ file='System.Data.dll'; product='.NET Framework 4 System.Data.dll' },
  @{ file='System.Configuration.dll'; product='.NET Framework 4 System.Configuration.dll' },
  @{ file='System.Drawing.dll'; product='.NET Framework 4 System.Drawing.dll' },
  @{ file='System.Windows.Forms.dll'; product='.NET Framework 4 System.Windows.Forms.dll' }
)
foreach ($d in $fxDlls) {
  $p = Join-Path $fxDir $d.file
  if (-not (Test-Path $p)) { continue }
  $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($p)
  if (-not $vi.FileVersion) { continue }
  $numeric = ('{0}.{1}.{2}.{3}' -f $vi.FileMajorPart,$vi.FileMinorPart,$vi.FileBuildPart,$vi.FilePrivatePart)
  $versions = @(
    [PSCustomObject]@{ source='file_version_numeric'; value=$numeric; observed_at=(Get-Date).ToUniversalTime().ToString('o') },
    [PSCustomObject]@{ source='file_version_raw'; value=$vi.FileVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') }
  )
  Add-App ([PSCustomObject]@{
    entity_type='application'
    entity_id=('app:file_version:netfx:' + $d.file)
    product_name=$d.product
    normalized_name=$d.product.ToLowerInvariant()
    display_version=$numeric
    file_version_raw=$vi.FileVersion
    file_major=$vi.FileMajorPart
    file_minor=$vi.FileMinorPart
    file_build=$vi.FileBuildPart
    file_private=$vi.FilePrivatePart
    publisher='Microsoft Corporation'
    install_scope='machine'
    path=$p
    source_type='file_version'
    version_evidence=$versions
  })
}

# PowerShell
$psVer = $PSVersionTable.PSVersion.ToString()
Add-App ([PSCustomObject]@{
  entity_type='application'; entity_id='app:adapter:powershell'
  product_name='PowerShell'; normalized_name='powershell'
  display_version=$psVer; publisher='Microsoft Corporation'
  install_scope='machine'; source_type='product_adapter'; adapter='powershell'
  version_evidence=@([PSCustomObject]@{ source='psversiontable'; value=$psVer; observed_at=(Get-Date).ToUniversalTime().ToString('o') })
})

# OpenSSH for Windows (optional feature / service)
$sshd = Get-Service sshd -EA SilentlyContinue
if ($sshd) {
  $sshPath = "$env:SystemRoot\System32\OpenSSH\sshd.exe"
  $versions = @()
  if (Test-Path $sshPath) {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($sshPath)
    if ($vi.ProductVersion) { $versions += [PSCustomObject]@{ source='pe_file_version'; value=$vi.ProductVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id='app:adapter:openssh'
    product_name='OpenSSH for Windows'; normalized_name='openssh for windows'
    display_version= if ($versions.Count -gt 0) { $versions[0].value } else { $null }
    publisher='Microsoft Corporation'; install_scope='machine'
    install_location="$env:SystemRoot\System32\OpenSSH"
    source_type='product_adapter'; adapter='openssh'; service_names=@('sshd')
    version_evidence=$versions
  })
}

# Chrome
foreach ($chrome in @(
  'HKLM:\SOFTWARE\Google\Chrome\BLBeacon',
  'HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon'
)) {
  if (Test-Path $chrome) {
    $c = Get-ItemProperty $chrome
    $versions = @()
    if ($c.version) { $versions += [PSCustomObject]@{ source='chrome_blbeacon'; value=$c.version; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
    Add-App ([PSCustomObject]@{
      entity_type='application'; entity_id='app:adapter:chrome'
      product_name='Google Chrome'; normalized_name='google chrome'
      display_version=$c.version; publisher='Google LLC'
      install_scope='machine'; source_type='product_adapter'; adapter='chrome'
      version_evidence=$versions
    })
    break
  }
}

# Firefox
$ff = 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox'
if (Test-Path $ff) {
  $cur = (Get-ItemProperty $ff -EA SilentlyContinue).CurrentVersion
  if ($cur) {
    $versions = @([PSCustomObject]@{ source='firefox_registry'; value=$cur; observed_at=(Get-Date).ToUniversalTime().ToString('o') })
    Add-App ([PSCustomObject]@{
      entity_type='application'; entity_id='app:adapter:firefox'
      product_name='Mozilla Firefox'; normalized_name='mozilla firefox'
      display_version=$cur; publisher='Mozilla'
      install_scope='machine'; source_type='product_adapter'; adapter='firefox'
      version_evidence=$versions
    })
  }
}

# Office Click-to-Run
$c2r = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
if (Test-Path $c2r) {
  $o = Get-ItemProperty $c2r
  $versions = @()
  if ($o.VersionToReport) { $versions += [PSCustomObject]@{ source='office_c2r_version'; value=$o.VersionToReport; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  if ($o.ClientVersionToReport) { $versions += [PSCustomObject]@{ source='office_c2r_client_version'; value=$o.ClientVersionToReport; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id='app:adapter:office_c2r'
    product_name= if ($o.ProductReleaseIds) { 'Microsoft Office Click-to-Run (' + $o.ProductReleaseIds + ')' } else { 'Microsoft Office Click-to-Run' }
    normalized_name='microsoft office click-to-run'
    display_version=$o.VersionToReport; publisher='Microsoft Corporation'
    install_scope='machine'; install_location=$o.InstallationPath
    source_type='product_adapter'; adapter='office_c2r'
    product_release_ids=$o.ProductReleaseIds
    update_channel=$o.UpdateChannel
    version_evidence=$versions
  })
}

# SQL Server instances (services + registry)
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -EA SilentlyContinue | ForEach-Object {
  $ip = Join-Path $_.PSPath 'MSSQLServer\CurrentVersion'
  if (Test-Path $ip) {
    $cv = Get-ItemProperty $ip
    $ver = $cv.CurrentVersion
    $versions = @()
    if ($ver) { $versions += [PSCustomObject]@{ source='sql_currentversion'; value=$ver; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
    Add-App ([PSCustomObject]@{
      entity_type='application'; entity_id=('app:adapter:sqlserver:' + $_.PSChildName)
      product_name=('Microsoft SQL Server (' + $_.PSChildName + ')')
      normalized_name='microsoft sql server'
      display_version=$ver; publisher='Microsoft Corporation'
      install_scope='machine'; source_type='product_adapter'; adapter='sqlserver'
      instance_id=$_.PSChildName; version_evidence=$versions
    })
  }
}

# IIS
$iis = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -EA SilentlyContinue
if ($iis) {
  $versions = @()
  if ($iis.VersionString) { $versions += [PSCustomObject]@{ source='inetstp_version'; value=$iis.VersionString; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id='app:adapter:iis'
    product_name='Internet Information Services'; normalized_name='internet information services'
    display_version=$iis.VersionString; publisher='Microsoft Corporation'
    install_scope='machine'; source_type='product_adapter'; adapter='iis'
    major_version=$iis.MajorVersion; minor_version=$iis.MinorVersion
    version_evidence=$versions
  })
}

# Modern .NET (hostfxr / DOTNET_ROOT style)
$dotnet = Get-Command dotnet -EA SilentlyContinue
if ($dotnet) {
  $versions = @()
  # Do not execute arbitrary user content; only allowlisted dotnet --list-runtimes is evidence-safe.
  try {
    $runtimes = & dotnet --list-runtimes 2>$null
    if ($runtimes) {
      $versions += [PSCustomObject]@{ source='dotnet_list_runtimes'; value=($runtimes -join '; '); observed_at=(Get-Date).ToUniversalTime().ToString('o') }
    }
  } catch {}
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id='app:adapter:dotnet'
    product_name='.NET'; normalized_name='.net'
    display_version= if ($versions.Count -gt 0) { ($versions[0].value -split ';')[0] } else { $null }
    publisher='Microsoft Corporation'; install_scope='machine'
    install_location=$dotnet.Source; source_type='product_adapter'; adapter='dotnet'
    version_evidence=$versions
  })
}

# Java (allowlisted java.exe near PATH / common dirs — version via file PE, not java -version execution of unknown builds when possible)
$javaCandidates = @(
  "$env:JAVA_HOME\bin\java.exe",
  'C:\Program Files\Java\*\bin\java.exe',
  'C:\Program Files\Eclipse Adoptium\*\bin\java.exe',
  'C:\Program Files\Microsoft\jdk-*\bin\java.exe'
)
Get-ChildItem $javaCandidates -EA SilentlyContinue | Select-Object -First 3 | ForEach-Object {
  $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)
  $versions = @()
  if ($vi.ProductVersion) { $versions += [PSCustomObject]@{ source='pe_file_version'; value=$vi.ProductVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  if ($vi.FileVersion) { $versions += [PSCustomObject]@{ source='pe_file_version_file'; value=$vi.FileVersion; observed_at=(Get-Date).ToUniversalTime().ToString('o') } }
  Add-App ([PSCustomObject]@{
    entity_type='application'; entity_id=('app:adapter:java:' + $_.Directory.Parent.Name)
    product_name= if ($vi.ProductName) { $vi.ProductName } else { 'Java' }
    normalized_name='java'
    display_version=$vi.ProductVersion; publisher=$vi.CompanyName
    install_scope='machine'; install_location=$_.Directory.Parent.FullName
    source_type='product_adapter'; adapter='java'; version_evidence=$versions
  })
}

# Deduplicate by product_name+source_type+entity_id already unique; emit JSON
$rows | ConvertTo-Json -Compress -Depth 6
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
	checkFiles(ctx, rows, m.Probes, runPowerShell)
	for _, row := range rows {
		// Preserve conflicting version_evidence as-is; do not silently pick one.
		if _, ok := row["entity_type"]; !ok {
			row["entity_type"] = "application"
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", row, nil))
	}
	common.Finish(&res, started, "success")
	return res
}

// Improve WUA taxonomy: products / classifications / categories separation.
func enrichWUAUpdateRow(u map[string]any) map[string]any {
	// Migrate legacy categories dump into classifications when possible.
	if _, ok := u["products"]; !ok {
		u["products"] = []any{}
	}
	if _, ok := u["classifications"]; !ok {
		u["classifications"] = []any{}
	}
	if cats, ok := u["categories"].([]any); ok {
		var products, classifications, other []any
		for _, c := range cats {
			s := strings.ToLower(asString(c))
			switch {
			case strings.Contains(s, "security") || strings.Contains(s, "critical") || strings.Contains(s, "update rollup") ||
				strings.Contains(s, "definition") || strings.Contains(s, "feature pack") || strings.Contains(s, "driver") ||
				strings.Contains(s, "preview") || strings.Contains(s, "upgrade"):
				classifications = append(classifications, c)
			case strings.Contains(s, "windows") || strings.Contains(s, "microsoft") || strings.Contains(s, "server") ||
				strings.Contains(s, "office") || strings.Contains(s, "sql"):
				products = append(products, c)
			default:
				other = append(other, c)
			}
		}
		if len(products) > 0 {
			u["products"] = products
		}
		if len(classifications) > 0 {
			u["classifications"] = classifications
		}
		u["categories"] = other
	}
	return u
}
