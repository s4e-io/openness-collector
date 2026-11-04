package windows

import (
	"context"
	"encoding/json"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

// LanguageDeps discovers Windows language-package identity from on-disk manifests
// and binary file metadata only (pip METADATA, npm package.json, NuGet nuspec,
// go.mod, GOROOT VERSION, PE FileVersionInfo). It does not execute interpreters
// or package managers (no python -c, node -v, npm, go version). ARP display
// names are not used. Caps keep the collect bounded.
type LanguageDeps struct{}

func (m *LanguageDeps) ID() string          { return "language_deps" }
func (m *LanguageDeps) Version() string     { return "1.0.0" }
func (m *LanguageDeps) Platforms() []string { return []string{"windows"} }

func (m *LanguageDeps) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	script := `
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$maxPip = 400
$maxNpm = 400
$maxNuget = 400
$maxGoMod = 40
$entities = @()
$notes = @()
$partial = $false

function Add-Entity($obj) { $script:entities += $obj }

# --- Python: site-packages METADATA (ecosystem=PyPI identity) ---
$pyRoots = @()
foreach ($cand in @(
  'C:\Python311','C:\Python39','C:\Python312','C:\Python310','C:\Python38',
  (Join-Path ${env:ProgramFiles} 'Python311'),
  (Join-Path ${env:ProgramFiles} 'Python39')
)) {
  if ($cand -and (Test-Path $cand)) { $pyRoots += $cand }
}
Get-ChildItem 'C:\' -Directory -Filter 'Python*' -EA SilentlyContinue | ForEach-Object { $pyRoots += $_.FullName }
# Store-style installs: %LOCALAPPDATA%\Programs\Python\Python3*\python.exe
$lap = Join-Path $env:LOCALAPPDATA 'Programs\Python'
if ($lap -and (Test-Path $lap)) {
  Get-ChildItem $lap -Directory -EA SilentlyContinue | ForEach-Object {
    if (Test-Path (Join-Path $_.FullName 'python.exe')) { $pyRoots += $_.FullName }
  }
}
$pyRoots = @($pyRoots | Select-Object -Unique)
$pipCount = 0
:pipLoop foreach ($root in $pyRoots) {
  $pyExe = Join-Path $root 'python.exe'
  $ver = $null
  if (Test-Path $pyExe) {
    try {
      $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($pyExe)
      $ver = $vi.ProductVersion
      if (-not $ver) { $ver = $vi.FileVersion }
    } catch {}
    Add-Entity ([PSCustomObject]@{
      entity_type = 'language_runtime'
      entity_id = ('lang:python:runtime:' + ($root -replace '[^A-Za-z0-9]+','-').ToLowerInvariant())
      language = 'python'
      ecosystem = 'PyPI'
      runtime_path = $pyExe
      runtime_version = $ver
      application_root = $root
      discovery_seed = 'install_path'
    })
  }
  $siteDirs = @()
  Get-ChildItem (Join-Path $root 'Lib\site-packages') -Directory -Filter '*.dist-info' -EA SilentlyContinue | ForEach-Object { $siteDirs += $_ }
  Get-ChildItem (Join-Path $root 'Lib\site-packages') -Directory -Filter '*.egg-info' -EA SilentlyContinue | ForEach-Object { $siteDirs += $_ }
  foreach ($di in $siteDirs) {
    if ($pipCount -ge $maxPip) { $partial = $true; $notes += 'pip_cap_reached'; break pipLoop }
    $metaPath = Join-Path $di.FullName 'METADATA'
    if (-not (Test-Path $metaPath)) { $metaPath = Join-Path $di.FullName 'PKG-INFO' }
    if (-not (Test-Path $metaPath)) { continue }
    $name = $null; $version = $null
    try {
      Get-Content $metaPath -TotalCount 40 -EA Stop | ForEach-Object {
        if ($_ -match '^Name:\s*(.+)$') { $name = $Matches[1].Trim() }
        if ($_ -match '^Version:\s*(.+)$') { $version = $Matches[1].Trim() }
      }
    } catch { continue }
    if (-not $name -or -not $version) { continue }
    # site-packages root — not the versioned *.dist-info folder name.
    $siteRoot = Split-Path $di.FullName -Parent
    $pathKey = ($siteRoot.ToLowerInvariant() -replace '[^a-z0-9]+','-')
    Add-Entity ([PSCustomObject]@{
      entity_type = 'python_distribution'
      # Stable id: name + site-packages path (version is a field only).
      entity_id = ('lang:python:dist:' + $name.ToLowerInvariant() + ':' + $pathKey)
      language = 'python'
      ecosystem = 'PyPI'
      name = $name
      name_normalized = $name.ToLowerInvariant()
      version = $version
      path = $di.FullName
      metadata_path = $metaPath
      runtime_root = $root
      state = 'installed'
      discovery_seed = 'dist_info'
      installation_origin = 'filesystem_site_packages'
      os_package_manager = $null
      os_binary_package = $null
      os_source_package = $null
      os_package_version = $null
      ownership_confidence = $null
    })
    $pipCount++
  }
}

# --- Node: runtime + global npm + package.json under known app roots ---
$nodeExe = $null
$pf86 = ${env:ProgramFiles(x86)}
foreach ($np in @(
  (Join-Path $env:ProgramFiles 'nodejs\node.exe'),
  $(if ($pf86) { Join-Path $pf86 'nodejs\node.exe' } else { $null })
)) {
  if ($np -and (Test-Path $np)) { $nodeExe = $np; break }
}
$npmCount = 0
if ($nodeExe) {
  $nodeVer = $null
  try {
    $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($nodeExe)
    $nodeVer = $vi.ProductVersion
    if (-not $nodeVer) { $nodeVer = $vi.FileVersion }
    if ($nodeVer) { $nodeVer = ([string]$nodeVer).TrimStart('v') }
  } catch {}
  Add-Entity ([PSCustomObject]@{
    entity_type = 'language_runtime'
    entity_id = 'lang:node:runtime:install'
    language = 'nodejs'
    ecosystem = 'npm'
    runtime_path = $nodeExe
    runtime_version = $nodeVer
    discovery_seed = 'install_path'
  })
  # Fixed paths only — never run npm.
  $npmRoots = @(
    (Join-Path $env:APPDATA 'npm\node_modules'),
    (Join-Path (Split-Path $nodeExe -Parent) 'node_modules'),
    (Join-Path $env:ProgramFiles 'nodejs\node_modules')
  ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
  :npmLoop foreach ($npmRoot in $npmRoots) {
    $dirs = @(Get-ChildItem $npmRoot -Directory -EA SilentlyContinue)
    foreach ($dir in $dirs) {
      if ($npmCount -ge $maxNpm) { $partial = $true; $notes += 'npm_cap_reached'; break npmLoop }
      $pkg = Join-Path $dir.FullName 'package.json'
      if (-not (Test-Path $pkg)) { continue }
      try {
        $meta = Get-Content $pkg -Raw -EA Stop | ConvertFrom-Json
        if (-not $meta.name -or -not $meta.version) { continue }
        $pathKey = ($dir.FullName.ToLowerInvariant() -replace '[^a-z0-9]+','-')
        Add-Entity ([PSCustomObject]@{
          entity_type = 'node_package'
          entity_id = ('lang:node:pkg:' + ([string]$meta.name).ToLowerInvariant() + ':' + $pathKey)
          language = 'nodejs'
          ecosystem = 'npm'
          name = [string]$meta.name
          version = [string]$meta.version
          path = $dir.FullName
          state = 'installed'
          scope = 'global'
          discovery_seed = 'npm_node_modules_path'
        })
        $npmCount++
      } catch {}
    }
  }
}

# --- Go: GOROOT VERSION file + go.mod under known roots (bounded); never run go.exe ---
$goExe = $null
foreach ($gp in @(
  (Join-Path ${env:ProgramFiles} 'Go\bin\go.exe'),
  (Join-Path $env:USERPROFILE 'go\bin\go.exe'),
  'C:\Go\bin\go.exe'
)) {
  if ($gp -and (Test-Path $gp)) { $goExe = $gp; break }
}
$goVersion = $null
if ($goExe) {
  $goRoot = Split-Path (Split-Path $goExe -Parent) -Parent
  $verFile = Join-Path $goRoot 'VERSION'
  if (Test-Path $verFile) {
    try {
      $raw = (Get-Content $verFile -TotalCount 1 -EA Stop).Trim()
      if ($raw -match 'go?([0-9]+\.[0-9]+(\.[0-9]+)?)') { $goVersion = $Matches[1] }
      elseif ($raw) { $goVersion = $raw.TrimStart('go') }
    } catch {}
  }
  if (-not $goVersion) {
    try {
      $vi = [Diagnostics.FileVersionInfo]::GetVersionInfo($goExe)
      $goVersion = $vi.ProductVersion
      if (-not $goVersion) { $goVersion = $vi.FileVersion }
    } catch {}
  }
  Add-Entity ([PSCustomObject]@{
    entity_type = 'language_runtime'
    entity_id = 'lang:go:runtime:install'
    language = 'go'
    ecosystem = 'Go'
    runtime_path = $goExe
    runtime_version = $goVersion
    discovery_seed = 'install_path'
  })
}
$goModCount = 0
$goSearchRoots = @(
  'C:\Users\Public',
  (Join-Path $env:USERPROFILE 'go\src'),
  (Join-Path $env:USERPROFILE 'source'),
  (Join-Path $env:USERPROFILE 'projects')
) | Where-Object { $_ -and (Test-Path $_) }
:gomodLoop foreach ($root in $goSearchRoots) {
  if ($goModCount -ge $maxGoMod) { break }
  $mods = @(Get-ChildItem $root -Filter 'go.mod' -Recurse -Depth 4 -File -EA SilentlyContinue)
  foreach ($modFile in $mods) {
    if ($goModCount -ge $maxGoMod) { $partial = $true; $notes += 'gomod_cap_reached'; break gomodLoop }
    $modPath = $modFile.FullName
    $module = $null; $modVer = $null
    try {
      Get-Content $modPath -TotalCount 20 -EA Stop | ForEach-Object {
        if ($_ -match '^module\s+(\S+)') { $module = $Matches[1] }
        if ($_ -match '^go\s+(\S+)') { $modVer = $Matches[1] }
      }
    } catch { continue }
    if (-not $module) { continue }
    Add-Entity ([PSCustomObject]@{
      entity_type = 'go_module'
      entity_id = ('lang:go:mod:' + ($module -replace '[^A-Za-z0-9._/\-]+','-') + ':' + ($modPath.ToLowerInvariant() -replace '[^a-z0-9]+','-'))
      language = 'go'
      ecosystem = 'Go'
      module_path = $module
      go_directive = $modVer
      path = $modPath
      runtime_version = $null
      state = 'observed'
      discovery_seed = 'go_mod'
    })
    $goModCount++
  }
}

# --- NuGet: user global packages cache (nuspec identity) ---
$nugetRoots = @(
  (Join-Path $env:USERPROFILE '.nuget\packages'),
  (Join-Path $env:ProgramData 'NuGet\packages')
) | Where-Object { $_ -and (Test-Path $_) }
$nugetCount = 0
:nugetLoop foreach ($nroot in $nugetRoots) {
  $pkgDirs = @(Get-ChildItem $nroot -Directory -EA SilentlyContinue)
  foreach ($pkgDir in $pkgDirs) {
    $pkgName = $pkgDir.Name
    $verDirs = @(Get-ChildItem $pkgDir.FullName -Directory -EA SilentlyContinue)
    foreach ($verDir in $verDirs) {
      if ($nugetCount -ge $maxNuget) { $partial = $true; $notes += 'nuget_cap_reached'; break nugetLoop }
      $ver = $verDir.Name
      $nuspec = Get-ChildItem $verDir.FullName -Filter '*.nuspec' -File -EA SilentlyContinue | Select-Object -First 1
      $id = $pkgName
      if ($nuspec) {
        try {
          [xml]$nx = Get-Content $nuspec.FullName -Raw -EA Stop
          if ($nx.package.metadata.id) { $id = [string]$nx.package.metadata.id }
          if ($nx.package.metadata.version) { $ver = [string]$nx.package.metadata.version }
        } catch {}
      }
      # Package folder only (exclude version subdir) so upgrades keep the same entity_id.
      $pathKey = ($pkgDir.FullName.ToLowerInvariant() -replace '[^a-z0-9]+','-')
      Add-Entity ([PSCustomObject]@{
        entity_type = 'nuget_package'
        entity_id = ('lang:nuget:pkg:' + $id.ToLowerInvariant() + ':' + $pathKey)
        language = 'dotnet'
        ecosystem = 'NuGet'
        name = $id
        version = $ver
        path = $verDir.FullName
        state = 'installed'
        discovery_seed = 'nuget_cache'
      })
      $nugetCount++
    }
  }
}

[PSCustomObject]@{
  entity_type = 'language_deps_summary'
  entity_id = 'lang:windows:summary'
  status = if ($partial) { 'partial' } else { 'success' }
  partial = [bool]$partial
  notes = $notes
  counts = [PSCustomObject]@{
    entities = $entities.Count
    pip = $pipCount
    npm = $npmCount
    go_mod = $goModCount
    nuget = $nugetCount
  }
  entities = $entities
} | ConvertTo-Json -Compress -Depth 8
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+truncate(out, 400)))
		common.Finish(&res, started, "error")
		return res
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	// Summary without nested entities, then each entity as its own evidence row.
	ents, _ := payload["entities"].([]any)
	summary := map[string]any{}
	for k, v := range payload {
		if k == "entities" {
			continue
		}
		summary[k] = v
	}
	summary["entity_count"] = len(ents)
	res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", summary, map[string]string{"raw_json": truncate(out, 2000)}))
	for _, e := range ents {
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", e, nil))
	}
	status := "success"
	if p, _ := payload["partial"].(bool); p {
		status = "partial"
		res.Errors = append(res.Errors, common.Err(m.ID(), "partial", "language_deps caps reached; see notes"))
	}
	common.Finish(&res, started, status)
	return res
}
