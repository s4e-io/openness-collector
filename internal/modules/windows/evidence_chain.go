package windows

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/s4e-io/openness-collector/internal/modules/common"
	"github.com/s4e-io/openness-collector/internal/schema"
)

const maxChainHashBytes = 32 * 1024 * 1024
const maxChainBinaries = 40

// EvidenceChain builds listen→PID→process→exe→service→ServiceDll→PE chains.
type EvidenceChain struct{}

func (m *EvidenceChain) ID() string          { return "evidence_chain" }
func (m *EvidenceChain) Version() string     { return "1.1.0" }
func (m *EvidenceChain) Platforms() []string { return []string{"windows"} }

func (m *EvidenceChain) Run(ctx context.Context) schema.ModuleResult {
	started := time.Now()
	res := common.NewResult(m.ID(), m.Version())

	script := psResolveProcessPath + `
$ErrorActionPreference = 'SilentlyContinue'
function Get-PEMeta($path) {
  if (-not $path) { return $null }
  $p = [Environment]::ExpandEnvironmentVariables($path.Trim('"'))
  if (-not (Test-Path -LiteralPath $p)) {
    return [PSCustomObject]@{ path = $p; exists = $false; file_version = $null; product_version = $null; product_name = $null; company_name = $null; original_filename = $null; size = $null; signature_status = 'not_found'; signer_subject = $null; signer_issuer = $null; catalog_signed = $null }
  }
  $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
  $item = Get-Item -LiteralPath $p
  $sigStatus = 'unsigned'
  $signer = $null
  $issuer = $null
  $catalog = $null
  try {
    $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop
    switch ([string]$sig.Status) {
      'Valid' { $sigStatus = 'valid' }
      'NotSigned' { $sigStatus = 'unsigned' }
      'HashMismatch' { $sigStatus = 'invalid' }
      'NotTrusted' { $sigStatus = 'untrusted_root' }
      'UnknownError' { $sigStatus = 'error' }
      default { $sigStatus = ([string]$sig.Status).ToLower() }
    }
    if ($sig.SignerCertificate) {
      $signer = $sig.SignerCertificate.Subject
      $issuer = $sig.SignerCertificate.Issuer
    }
    # Catalog vs embedded: SignatureType if available
    try { if ($sig.SignatureType) { $catalog = ([string]$sig.SignatureType -match 'Catalog') } } catch {}
  } catch {
    $sigStatus = 'error'
  }
  return [PSCustomObject]@{
    path = $p
    exists = $true
    size = $item.Length
    file_version = $vi.FileVersion
    product_version = $vi.ProductVersion
    product_name = $vi.ProductName
    company_name = $vi.CompanyName
    original_filename = $vi.OriginalFilename
    file_description = $vi.FileDescription
    signature_status = $sigStatus
    signer_subject = $signer
    signer_issuer = $issuer
    catalog_signed = $catalog
  }
}
function Resolve-ServiceDll($name) {
  $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
  $params = "$reg\Parameters"
  $dll = $null
  if (Test-Path $params) { $dll = (Get-ItemProperty $params -EA SilentlyContinue).ServiceDll }
  $img = (Get-ItemProperty $reg -EA SilentlyContinue).ImagePath
  return [PSCustomObject]@{ service_dll = $dll; image_path = $img }
}
$apps = @()
foreach ($p in @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)) {
  Get-ItemProperty $p -EA SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
    $apps += [PSCustomObject]@{
      display_name = $_.DisplayName
      display_version = $_.DisplayVersion
      publisher = $_.Publisher
      install_location = $_.InstallLocation
    }
  }
}
$svcByPid = @{}
Get-CimInstance Win32_Service | ForEach-Object {
  $owningPid = [int]$_.ProcessId
  if ($owningPid -le 0) { return }
  if (-not $svcByPid.ContainsKey($owningPid)) { $svcByPid[$owningPid] = @() }
  $extra = Resolve-ServiceDll $_.Name
  $svcByPid[$owningPid] += [PSCustomObject]@{
    name = $_.Name
    display_name = $_.DisplayName
    state = $_.State
    path_name = $_.PathName
    process_id = $owningPid
    service_dll = $extra.service_dll
    image_path = $extra.image_path
  }
}
$listeners = @()
Get-NetTCPConnection -State Listen -EA SilentlyContinue | ForEach-Object {
  $listeners += [PSCustomObject]@{
    protocol = 'tcp'
    local_address = $_.LocalAddress
    local_port = [int]$_.LocalPort
    owning_pid = [int]$_.OwningProcess
  }
}
Get-NetUDPEndpoint -EA SilentlyContinue | ForEach-Object {
  $listeners += [PSCustomObject]@{
    protocol = 'udp'
    local_address = $_.LocalAddress
    local_port = [int]$_.LocalPort
    owning_pid = [int]$_.OwningProcess
  }
}
$chains = @()
foreach ($l in $listeners) {
  $owningPid = [int]$l.owning_pid
  $proc = $null
  $pathStatus = $null
  $pathSource = $null
  if ($owningPid -gt 0) {
    $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$owningPid" -EA SilentlyContinue
    $resolved = Resolve-ProcessImagePath -ProcessId $owningPid -Name $(if ($wp) { $wp.Name } else { $null }) -CimPath $(if ($wp) { $wp.ExecutablePath } else { $null })
    $pathStatus = $resolved.path_status
    $pathSource = $resolved.path_source
    if ($wp -or $resolved.executable_path -or $resolved.path_status) {
      $proc = [PSCustomObject]@{
        pid = $owningPid
        ppid = if ($wp) { [int]$wp.ParentProcessId } else { $null }
        name = if ($wp) { $wp.Name } else { $null }
        executable_path = $resolved.executable_path
        path_source = $resolved.path_source
        path_status = $resolved.path_status
        known_component = $resolved.known_component
        command_line = if ($wp) { $wp.CommandLine } else { $null }
      }
    }
  }
  $services = @()
  if ($owningPid -gt 0 -and $svcByPid.ContainsKey($owningPid)) { $services = $svcByPid[$owningPid] }
  $exePath = $null
  if ($proc -and $proc.executable_path) { $exePath = $proc.executable_path }
  # Fallback: native service binary path when process path unresolved
  if (-not $exePath -and $services.Count -gt 0) {
    foreach ($sv in $services) {
      $candidate = $null
      if ($sv.service_dll) { $candidate = $sv.service_dll }
      elseif ($sv.path_name -match '^"([^"]+)"') { $candidate = $Matches[1] }
      elseif ($sv.path_name) { $candidate = ($sv.path_name -split '\s+')[0] }
      if ($candidate) {
        $exePath = [Environment]::ExpandEnvironmentVariables($candidate.Trim('"'))
        $pathSource = 'service_binary_path'
        $pathStatus = 'resolved_via_service'
        if ($proc) {
          $proc.executable_path = $exePath
          $proc.path_source = $pathSource
          $proc.path_status = $pathStatus
        }
        break
      }
    }
  }
  $pe = Get-PEMeta $exePath
  $svcDllPE = $null
  $primarySvc = $null
  if ($services.Count -gt 0) {
    $primarySvc = $services[0]
    if ($primarySvc.service_dll) { $svcDllPE = Get-PEMeta $primarySvc.service_dll }
  }
  $app = $null
  if ($exePath) {
    $dir = Split-Path -Parent $exePath
    foreach ($a in $apps) {
      if ($a.install_location -and $dir -and ($dir.StartsWith($a.install_location.TrimEnd('\','/'), [StringComparison]::OrdinalIgnoreCase))) {
        $app = $a; break
      }
    }
  }
  $chains += [PSCustomObject]@{
    socket = $l
    process = $proc
    services = $services
    primary_service = $primarySvc
    binary = $pe
    service_dll = $svcDllPE
    application = $app
  }
}
$chains | ConvertTo-Json -Compress -Depth 8
`
	out, err := runPowerShell(ctx, script)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", err.Error()+": "+truncate(out, 500)))
		common.Finish(&res, started, "error")
		return res
	}
	rows, err := decodeJSONRows(out)
	if err != nil {
		res.Errors = append(res.Errors, common.Err(m.ID(), "collection_error", "json parse: "+err.Error()))
		common.Finish(&res, started, "error")
		return res
	}
	if len(rows) == 0 {
		res.Errors = append(res.Errors, common.Err(m.ID(), "unavailable", "no listening endpoints discovered"))
		common.Finish(&res, started, "unavailable")
		return res
	}

	hashCache := map[string]string{}
	hashed := 0
	anyIncomplete := false

	for _, row := range rows {
		select {
		case <-ctx.Done():
			res.Errors = append(res.Errors, common.Err(m.ID(), "timeout", "evidence chain cancelled"))
			common.Finish(&res, started, "partial")
			return res
		default:
		}

		sockRaw, _ := row["socket"].(map[string]any)
		proto := strings.ToLower(asString(sockRaw["protocol"]))
		if proto == "" {
			proto = "tcp"
		}
		addr := asString(sockRaw["local_address"])
		port := asInt(sockRaw["local_port"])
		pid := asInt(sockRaw["owning_pid"])
		loopback := addr == "127.0.0.1" || addr == "::1" || strings.EqualFold(addr, "localhost")
		wildcard := addr == "0.0.0.0" || addr == "::" || addr == "*"
		family := "ipv4"
		if strings.Contains(addr, ":") && !strings.Contains(addr, ".") {
			family = "ipv6"
		}
		sock := map[string]any{
			"entity_id":         entitySocket(proto, addr, port),
			"entity_type":       "socket",
			"protocol":          proto,
			"address_family":    family,
			"local_address":     addr,
			"local_port":        port,
			"owning_pid":        nullIfZero(pid),
			"loopback_only":     loopback,
			"wildcard_binding":  wildcard,
			"state":             "listen",
			"process_entity_id": nil,
		}

		chain := []string{"socket"}
		rels := []map[string]any{}
		var proc map[string]any
		var binary map[string]any
		var service map[string]any
		var serviceDLL map[string]any
		var application map[string]any
		complete := false
		gap := ""

		if pid <= 0 {
			gap = "owning_pid_unavailable"
			anyIncomplete = true
		} else if row["process"] == nil {
			gap = "permission_denied"
			anyIncomplete = true
			res.Errors = append(res.Errors, common.Err(m.ID(), "PROCESS_ACCESS_DENIED", "pid="+asString(pid)))
		} else if pm, ok := row["process"].(map[string]any); ok {
			exe := asString(pm["executable_path"])
			procName := asString(pm["name"])
			cmdline := RedactSecrets(asString(pm["command_line"]))
			proc = map[string]any{
				"entity_id":        entityProcess(pid),
				"entity_type":      "process",
				"pid":              pid,
				"ppid":             asInt(pm["ppid"]),
				"name":             procName,
				"executable_path":  nullIfEmpty(exe),
				"path_source":      nullIfEmpty(asString(pm["path_source"])),
				"path_status":      nullIfEmpty(asString(pm["path_status"])),
				"command_line":     nullIfEmpty(cmdline),
				"binary_entity_id": nil,
				"service_names":    []string{},
			}
			if kc := asString(pm["known_component"]); kc != "" {
				proc["known_component"] = kc
			}
			sock["process_entity_id"] = proc["entity_id"]
			sock["process_name"] = proc["name"]
			chain = append(chain, "process")
			rels = append(rels, map[string]any{
				"type": "process_listens_on_socket", "source_entity_id": proc["entity_id"],
				"target_entity_id": sock["entity_id"], "confidence": "direct", "evidence_source": "get_net_connection",
			})

			// Kernel / protected system process without usable image path
			if exe == "" {
				if mapped := knownWindowsProcessPath(procName); mapped != "" {
					exe = mapped
				}
			}
			if exe == "" && (pid == 4 || strings.EqualFold(procName, "System") || strings.EqualFold(procName, "Registry")) {
				gap = "kernel_owned_socket"
				anyIncomplete = true
			} else if exe != "" {
				proc["binary_entity_id"] = entityBinary(exe)
				binary = peFromMap(row["binary"], exe)
				if binary != nil {
					chain = append(chain, "binary")
					rels = append(rels, map[string]any{
						"type": "process_executed_binary", "source_entity_id": proc["entity_id"],
						"target_entity_id": binary["entity_id"], "confidence": "direct", "evidence_source": "win32_process",
					})
					if path := asString(binary["path"]); path != "" && asBool(binary["exists"]) {
						maybeHash(binary, path, hashCache, &hashed)
					}
					if !asBool(binary["exists"]) {
						gap = "binary_not_found"
					}
				}
			} else {
				gap = "process_path_unavailable"
				anyIncomplete = true
			}

			svcNames := []string{}
			if services, ok := row["services"].([]any); ok {
				for _, s := range services {
					if sm, ok := s.(map[string]any); ok {
						svcNames = append(svcNames, asString(sm["name"]))
					}
				}
			}
			proc["service_names"] = svcNames

			if ps, ok := row["primary_service"].(map[string]any); ok && ps != nil {
				name := asString(ps["name"])
				img := RedactSecrets(asString(ps["path_name"]))
				binPath, args := parseImagePath(img)
				binPath = RedactSecrets(binPath)
				group := svchostGroupFromArgs(args)
				dll := asString(ps["service_dll"])
				if dll != "" {
					dll = os.ExpandEnv(expandWindowsEnv(dll))
				}
				service = map[string]any{
					"entity_id":     entityService(name),
					"entity_type":   "service",
					"service_name":  name,
					"display_name":  asString(ps["display_name"]),
					"state":         asString(ps["state"]),
					"process_id":    asInt(ps["process_id"]),
					"binary_path":   nullIfEmpty(binPath),
					"path_name":     nullIfEmpty(img),
					"svchost_group": nullIfEmpty(group),
					"service_dll":   nullIfEmpty(dll),
					"registry_path": `HKLM\SYSTEM\CurrentControlSet\Services\` + name,
				}
				chain = append(chain, "service")
				rels = append(rels, map[string]any{
					"type": "process_hosts_service", "source_entity_id": proc["entity_id"],
					"target_entity_id": service["entity_id"], "confidence": "direct", "evidence_source": "win32_service",
				})
				if binPath != "" {
					rels = append(rels, map[string]any{
						"type": "service_executes_binary", "source_entity_id": service["entity_id"],
						"target_entity_id": entityBinary(binPath), "confidence": "direct", "evidence_source": "service_imagepath",
					})
				}
				if dll != "" {
					serviceDLL = peFromMap(row["service_dll"], dll)
					if serviceDLL != nil {
						chain = append(chain, "service_dll")
						rels = append(rels, map[string]any{
							"type": "service_loads_dll", "source_entity_id": service["entity_id"],
							"target_entity_id": serviceDLL["entity_id"], "confidence": "direct", "evidence_source": "service_registry",
						})
						if path := asString(serviceDLL["path"]); path != "" && asBool(serviceDLL["exists"]) {
							maybeHash(serviceDLL, path, hashCache, &hashed)
						}
					} else {
						res.Errors = append(res.Errors, common.Err(m.ID(), "SERVICE_DLL_NOT_FOUND", dll))
					}
				}
			}

			if am, ok := row["application"].(map[string]any); ok && am != nil && asString(am["display_name"]) != "" {
				application = map[string]any{
					"entity_id":        "app:" + strings.ToLower(asString(am["display_name"])),
					"entity_type":      "application",
					"product_name":     asString(am["display_name"]),
					"display_version":  asString(am["display_version"]),
					"publisher":        asString(am["publisher"]),
					"install_location": asString(am["install_location"]),
				}
				chain = append(chain, "application")
				if binary != nil {
					rels = append(rels, map[string]any{
						"type": "binary_belongs_to_application", "source_entity_id": binary["entity_id"],
						"target_entity_id": application["entity_id"], "confidence": "inferred", "evidence_source": "uninstall_install_location",
					})
				}
			}

			// complete when we have process + existing binary; service preferred but not required
			complete = pid > 0 && binary != nil && asBool(binary["exists"])
			if service != nil && asString(service["service_dll"]) != "" && serviceDLL == nil {
				complete = false
				gap = "SERVICE_DLL_NOT_FOUND"
			}
			if !complete && gap == "" {
				if binary == nil {
					gap = "process_path_unavailable"
				} else if !asBool(binary["exists"]) {
					gap = "binary_not_found"
				} else {
					gap = "incomplete_chain"
				}
			}
		}

		if !complete {
			anyIncomplete = true
		}

		val := map[string]any{
			"entity_id":     "chain:" + asString(sock["entity_id"]),
			"entity_type":   "evidence_chain",
			"chain":         chain,
			"complete":      complete,
			"socket":        sock,
			"process":       proc,
			"binary":        binary,
			"service":       service,
			"service_dll":   serviceDLL,
			"application":   application,
			"relationships": rels,
		}
		if gap != "" {
			val["gap"] = gap
		}
		res.Evidence = append(res.Evidence, common.Evidence("native", m.ID(), "observed", val, nil))
	}

	status := "success"
	if anyIncomplete {
		status = "partial"
	}
	common.Finish(&res, started, status)
	return res
}

func peFromMap(v any, fallbackPath string) map[string]any {
	path := fallbackPath
	var m map[string]any
	if mm, ok := v.(map[string]any); ok {
		m = mm
		if p := asString(mm["path"]); p != "" {
			path = p
		}
	}
	path = normalizePath(expandWindowsEnv(path))
	if path == "" {
		return nil
	}
	out := map[string]any{
		"entity_id":         entityBinary(path),
		"entity_type":       "binary",
		"path":              path,
		"normalized_path":   path,
		"exists":            false,
		"size":              nil,
		"sha256":            nil,
		"file_version":      nil,
		"product_version":   nil,
		"product_name":      nil,
		"company_name":      nil,
		"original_filename": nil,
	}
	if m != nil {
		out["exists"] = asBool(m["exists"])
		for _, k := range []string{"file_version", "product_version", "product_name", "company_name", "original_filename", "file_description", "signature_status", "signer_subject", "signer_issuer"} {
			if s := asString(m[k]); s != "" {
				out[k] = s
			}
		}
		if m["catalog_signed"] != nil {
			out["catalog_signed"] = m["catalog_signed"]
		}
		if sz := asInt(m["size"]); sz > 0 {
			out["size"] = sz
		}
	}
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		out["exists"] = true
		out["size"] = st.Size()
	}
	return out
}

func maybeHash(bin map[string]any, path string, cache map[string]string, hashed *int) {
	if *hashed >= maxChainBinaries {
		return
	}
	sz := asInt(bin["size"])
	if sz <= 0 || int64(sz) > maxChainHashBytes {
		return
	}
	if h, ok := cache[path]; ok {
		bin["sha256"] = h
		return
	}
	h, err := sha256File(path)
	if err != nil {
		return
	}
	cache[path] = h
	bin["sha256"] = h
	*hashed++
}

func expandWindowsEnv(s string) string {
	// PowerShell already expands; handle common %VAR% left behind.
	replacer := strings.NewReplacer(
		"%SystemRoot%", os.Getenv("SystemRoot"),
		"%systemroot%", os.Getenv("SystemRoot"),
		"%windir%", os.Getenv("SystemRoot"),
		"%WINDIR%", os.Getenv("SystemRoot"),
		"%ProgramFiles%", os.Getenv("ProgramFiles"),
	)
	out := replacer.Replace(s)
	if out == "" {
		return s
	}
	return out
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func knownWindowsProcessPath(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	switch n {
	case "services.exe":
		return root + `\System32\services.exe`
	case "wininit.exe":
		return root + `\System32\wininit.exe`
	case "lsass.exe":
		return root + `\System32\lsass.exe`
	case "csrss.exe":
		return root + `\System32\csrss.exe`
	case "smss.exe":
		return root + `\System32\smss.exe`
	case "svchost.exe":
		return root + `\System32\svchost.exe`
	default:
		return ""
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
