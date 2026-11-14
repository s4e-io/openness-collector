# Collector modules

Every module, step by step, per operating system. The number after each module id is the module version.

[Back to README](../README.md)

## Linux modules: step by step

### `os_inventory` (1.2.0)

**Goal:** Identify the OS.

Steps:

1. Read `/etc/os-release`.
2. Read `/etc/machine-id`.
3. Read kernel release from `/proc/sys/kernel/osrelease`.
4. Read hostname / FQDN.
5. Detect timezone from `/etc/localtime`.
6. Detect init system (systemd if `/run/systemd/system` exists).
7. Observe `/var/run/reboot-required` and `.pkgs` → `reboot_required`, `reboot_required_packages`.
8. Emit one OS inventory object.

If os-release is missing → `unavailable`.

### `hardware_inventory` (1.0.0)

**Goal:** Basic CPU / memory / DMI identity.

Steps:

1. Read `/proc/cpuinfo`.
2. Read `/proc/meminfo`.
3. Read DMI sysfs fields (`sys_vendor`, `product_name`, serial, board).
4. Emit hardware object.

### `packages` (1.6.0)

**Goal:** Installed OS packages + source/repo metadata + remediation candidate observation.

Steps:

1. Prefer `dpkg-query -W` on Debian/Ubuntu. Without `dpkg-query`, parse `/var/lib/dpkg/status` directly. Also read distroless Debian `/var/lib/dpkg/status.d/*` (one stanza per file, `*.md5sums` ignored, a stanza without `Status` counts as installed); these records carry `collection_source: dpkg-status.d` in `raw_value`.
2. Optionally support `rpm -qa` where present. On Alpine, parse `/lib/apk/db/installed` directly (file parse only; no `apk` binary). `o:` (origin) is emitted as `source_package`.
3. For each package, capture name, version parts, arch, status.
4. Capture `Source` package when present.
5. Scan `/var/lib/apt/lists/*Packages*` for origin metadata (file parse only; never `apt-get` / `apt-cache`).
6. If a package matches APT lists → `installed_from_repository=true`.
7. If not found in lists → leave `installed_from_repository=null`.
8. Set `highest_list_version` / `highest_list_origin` from lists (arch-exact; no name-only fallback when arch known).
9. Set `lists_updated_at` (list file mtimes) and `apt_update_success_at` (periodic stamp) when present.
10. Emit relationship `package_built_from_source_package` when possible.
11. Set `origin` on every record (dpkg, rpm, apk): vendor, maintainer, repository URL, signing key id and the `basis` of each. See `docs/EVIDENCE.md`.

Important:

- We never invent `local/dpkg` as a fake repository.
- Unknown origin stays unknown.
- Candidate is list observation, not a recommended upgrade command.
- At most 20000 package records are kept. Reading stops at the cap (the package tool is killed), the module gets `truncated: true`, status `partial` and one error with code `package_limit_truncated`.
- Zero packages is never a clean result: status `unavailable` with error code `no_packages`. The message says whether no package database was found or a database was found but held no installed packages.

### `kernel_inventory` (1.1.0)

Steps:

1. Read running kernel version.
2. Read arch via `uname`.
3. List `/proc/modules`.
4. Observe `/var/run/reboot-required` and `/var/run/reboot-required.pkgs` → `reboot_required`, `reboot_required_packages`.
5. Emit kernel object.

(`os_inventory` **1.2.0** also emits the same reboot observation fields.)

### `services` (1.1.0)

Steps:

1. Run `systemctl list-units --type=service`.
2. Enrich a capped set with `systemctl show`.
3. Capture unit name, states, ExecStart, MainPID, user.
4. If MainPID exists, emit `process_belongs_to_service`.

### `processes` (1.1.0)

Steps:

1. Walk `/proc/<pid>/`.
2. Read `cmdline`, `status`, `exe`, `cwd`.
3. Resolve realpath of exe when possible.
4. Redact secret-like cmdline pieces.
5. Emit process entities.

We do not use `ps` as the primary source.

### `listening_ports` (1.1.0)

Steps:

1. Parse `/proc/net/tcp`, `tcp6`, `udp`, `udp6`.
2. Map socket inodes to PIDs via `/proc/*/fd`.
3. Emit socket entities (protocol, family, addr, port, pid).
4. Use `ss` only as a detection fallback, not as the main proof.

### `evidence_chain` (1.0.0)

See [section 12](#12-linux-evidence-chain-listen--package--repo).

### `loaded_libraries` (1.0.0)

See [section 17](#17-loaded-libraries).

### `containers` (1.3.0)

See [section 16](#16-containers).

### `language_deps` (1.1.3)

See [sections 14 and 15](#14-python-inventory-how-load-is-proven).

### `security_configuration` (1.2.0)

Steps:

1. Probe SELinux (`getenforce`) if present.
2. Probe AppArmor (`aa-status`) if present.
3. Probe UFW / firewalld / auditd state.
4. Check Secure Boot efivar presence.
5. Capture OpenSSH / sudo versions.
6. Read effective sshd settings with allowlisted `sshd -T` (read-only).
7. Emit probe maps. No vulnerability judgment.

### `users` (1.0.0)

Steps:

1. Read `/etc/passwd`.
2. Emit username, uid, gid, home, shell.
3. Do not emit password hashes.

### `network_inventory` (1.0.0)

Steps:

1. Prefer `ip -o addr show`.
2. Fallback to `ifconfig -a`.
3. Emit interface/address lines.

---

### `software_inventory` (1.1.0)

Catalog-driven detection of products that package managers describe poorly or
not at all: database servers, web servers, TLS libraries, SSH, Java runtimes.
Shared with Windows (same code, same catalog, `internal/modules/swinv`).

Steps:

1. Load the embedded catalog (`internal/modules/swinv/catalog/*.yaml`, version in `catalog_version`).
2. List running processes from `/proc` (pid, comm, exe link) and TCP listeners from `/proc/net/tcp*`.
3. For each catalog entry on this platform, collect install candidates from path globs, matching process executables and (Windows) registry keys.
4. For each candidate, run the entry's `version_readers`: `file_regex` (bounded binary scan), `zip_entry_regex` (jar/zip entry), `dir_names` / `file_regex` patch lists, `registry_value` and `pe_version` on Windows.
5. Emit one `software_instance` per install path with `version`, `version_source`, all `version_candidates`, `patch_ids`, signals (paths, processes, ports, registry) and `confidence` (`direct` or `presence_only`).
6. On Linux, ask the package databases which package owns each instance's files, in one lookup for all instances (dpkg file lists, apk installed database, one `rpm -qf`), and set `owner_package` / `owner_package_status`.
7. Emit `software_inventory_summary` first (catalog version, counts, caps, `owner_managers`).

Honesty:

- No product binary is ever executed (`nginx -v`, `sqlplus`, `opatch` are not run). Versions come from files, archives and registry only.
- A product seen without a readable version is still reported, with `version: null`, `gap: "version_unreadable"` and `confidence: "presence_only"`.
- `catalog_verified: false` on an instance means the catalog entry was written from vendor documentation and has not been exercised against a real install (Oracle Database, SQL Server at the time of writing). Treat its readers as unproven.
- Distro-packaged copies (for example `mysql-server` from apt) are also in `packages`; `software_inventory` adds the non-packaged installs and the version string actually embedded in the binary.
- `owner_package` is a fact, not a verdict. An instance owned by a package is the same software the `packages` record describes; whether to evaluate it once or twice is the consumer's call. `not_checked` is never reported as `not_owned`.
- Scope is the host root in this version. Container roots reuse the same detector but are not wired yet (`scopes` in the summary lists what was scanned).

Entity id: `sw:<product_key>:<scope>:<hash(install_path)>` (stable across upgrades; the version is a field).

---

## Windows modules: step by step

### `os_inventory` (1.1.0)

Steps:

1. Query CIM / registry for product name, build, UBR, display version.
2. Read MachineGuid.
3. Detect hostname / FQDN / domain.
4. Detect elevation (`admin` vs `user`).
5. Read reboot-pending indicators.
6. Emit OS inventory.

### `hardware_inventory` (1.0.0)

Steps:

1. Query CIM / PowerShell hardware classes.
2. Emit basic hardware record.

### `applications` (1.2.0)

Steps:

1. Read Uninstall registry (HKLM/HKCU, including WOW64).
2. Read AppX / MSIX where available.
3. Emit application entities with publisher, version evidence, install scope.
4. Do not crawl Win32_Product as primary inventory.

### `windows_features` (1.1.0)

Steps:

1. Read the Server Manager component cache from the registry (`HKLM\SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache`, native, milliseconds). Rows carry `source: servermanager_component_cache` and the raw `InstallState`; absent key (client SKUs) is simply zero rows.
2. Run `Get-WindowsOptionalFeature -Online` / `Get-WindowsFeature` with the module's **own 45 s deadline**. DISM/CBS can block for minutes when TrustedInstaller is busy; on timeout the module reports `FEATURE_API_TIMEOUT` instead of consuming the whole per-module budget.
3. Live DISM rows replace cache rows for the same role (`cache_install_state_raw` keeps what the cache said).
4. Emit a `windows_features_context` row first (`cache_rows`, `cmdlet_rows`, `cmdlet_duration_ms`, `cmdlet_status`).
5. Status: `success` when the cmdlets answered, `partial` when only the cache answered, `unavailable` when neither did.

### `cbs_packages` (1.0.0)

**Primary Windows package/update inventory.**

Steps:

1. Prefer `Get-WindowsPackage -Online` (DISM).
2. Fallback to CBS registry packages.
3. Capture package identity, KB id, and **state**.
4. Keep states honest: staged is not installed.
5. Include reboot-related bits when present.

### `patches` (1.1.0)

**Secondary only.**

Steps:

1. Run `Get-HotFix`.
2. Emit hotfix rows with `evidence_role=secondary_crosscheck`.
3. Do not treat HotFix as the primary installed-update source.

### `missing_updates` (1.2.0)

Steps:

1. Query Windows Update Agent for `IsInstalled=0`.
2. Capture update service / WSUS policy context.
3. Capture light update history.
4. Emit missing updates + `update_context`.
5. Do not install updates.

### `services` (1.2.1)

Steps:

1. Enumerate services (SCM / CIM).
2. Read ImagePath and `ServiceDll`.
3. Capture svchost group when relevant.
4. Emit service entities.

### `processes` (1.2.0)

Steps:

1. Enumerate processes.
2. Resolve image path (`QueryFullProcessImageName` → fallbacks).
3. Use known maps for System / Idle / Registry.
4. Redact secret-like cmdline content.
5. Emit process entities with path status.

If path is protected → explicit status, not a fake path.

### `listening_ports` (1.1.0)

Steps:

1. Query TCP listen sockets.
2. Query UDP endpoints.
3. Attach owning PID.
4. Emit socket entities.

### `evidence_chain` (1.1.0)

See [section 13](#13-windows-evidence-chain-listen--pe--app).

### `security_products` (1.0.0)

Steps:

1. Read Defender status when available.
2. Read firewall profiles.
3. Emit product snapshot.

### `security_configuration` (1.4.0)

Steps:

1. Read Defender preferences / runtime status.
2. Read firewall profile settings.
3. Tag settings with source (configured / effective / runtime).
4. Deep GPO precedence is still limited.
5. Read the registry value list (built-in table in `internal/modules/windows/security_registry.go` plus `--registry-values`) read-only and emit `registry`.

`registry` has exactly one object per listed value (a `\*` wildcard key gives one object per existing subkey):

```json
{"key": "SYSTEM\\CurrentControlSet\\Control\\Lsa", "name": "RunAsPPL", "hive": "HKLM", "present": true, "type": "DWord", "value": 1}
```

- Value not set (key or value missing): `present: false`, `value: null`, no `error`.
- Not collected (access denied, read failure, value not reported): `present: false`, `value: null`, `error` set (`access_denied`, `read_failed: <type>`, `hive_unavailable`, `not_reported`).
- Wildcard (`...\Interfaces\*`): concrete `key` plus `pattern` (the table key). No subkeys: one object with `key` = `pattern`, `present: false`.
- `type`: `DWord`, `QWord`, `String`, `ExpandString`, `MultiString`, `Binary`. DWord/QWord are unsigned; MultiString is an array; Binary is hex.
- Secrets are presence-only (`value` always `null`, the value is never read): Winlogon `DefaultPassword`, any name containing `password`, anything under `SECURITY\`, and names containing `secret` or `key` under Winlogon / LSA.

`--registry-values` adds values at run time. Format: base64url (padding optional) of a JSON array `[{"key": "SOFTWARE\\Policies\\...", "name": "X"}]`; optional `"hive": "HKLM"` and `"presence_only": true`. A leading `HKLM\` is stripped. Rules: HKLM only, no `..`, no empty path segments, `*` only as the last segment, at most 1000 entries. The inline argument is limited to 7000 characters (cmd.exe rejects command lines over 8191); for larger lists pass `@<path>` to a file with the JSON (or its base64url), up to 1 MiB. Entries already in the built-in table are deduplicated.

On hosts without `Get-SmbServerConfiguration` (2008 R2) the SMB server settings come from `LanmanServer\Parameters` with `source: registry_fallback`. Without `Get-TlsCipherSuite` (2012 R2 and older) `tls_schannel.cipher_suites` is `null` and `cipher_suites_source` is `unavailable`.

### `users` (1.0.0)

Steps:

1. Query local users.
2. Emit name, enabled, last logon, password_required, description.

### `network_inventory` (1.0.0)

Steps:

1. Query `Get-NetIPAddress`.
2. Emit interface / IP / family / prefix.

---

### `software_inventory` (1.1.0)

Same module and catalog as Linux (see 10.15). Windows specifics:

1. Processes via the toolhelp snapshot API; listeners via `GetTcpTable` (no WMI, no PowerShell).
2. Registry signals under `HKLM` (for example `SOFTWARE\PostgreSQL\Installations\*`, `SOFTWARE\MySQL AB\MySQL Server *`, `SOFTWARE\ORACLE\KEY_*`, `SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*`).
3. `pe_version` reads the fixed file version from the PE resource (`GetFileVersionInfo`), never by running the executable.
4. Paths are relative to the system drive (`Program Files\PostgreSQL\*`, `Windows\System32\OpenSSH\sshd.exe`, ...).
