# Known limitations

Current product versions in code: collector **0.9.0**, schema **1.6.0**.

Honest scope for assessors. A `collection.status=complete` result means selected modules finished without reported errors. It does **not** mean every possible OS surface was covered.

## Platforms actually tested

| Host | Role | Notes |
|---|---|---|
| Ubuntu (aarch64 / arm64) | Linux lab | Primary Linux evidence path |
| Windows Server 2022 (amd64) | WinRM lab | Primary Windows evidence path |
| Ubuntu 22.04 Docker (arm64) | Linux smoke | When SSH lab is unreachable |

## Cross-cutting

- **Local-only.** No remote SSH/WinRM/management inside the collector binary.
- **No CVE / OVAL / scoring.** Evidence only. Vulnerability matching is a separate resolver.
- **osquery is optional.** Native modules are primary.
- Endpoint state is never modified (no update install, EULA accept, service start).
- **APT highest-in-lists versions** come from parsing `/var/lib/apt/lists` only (`apt-get` / `apt-cache` are not executed). Stale lists: `lists_updated_at` (list file mtime) and `apt_update_success_at` (`/var/lib/apt/periodic/update-success-stamp` when present).
- **Livepatch / snap / offline wsusscn2** are not in 0.5.0 batch-1; absent livepatch surfaces as `null` + gap in a later module.
- **`software_inventory` catalog is small and host-scope only** (databases, web servers, OpenSSL, OpenSSH, Java). Entries marked `catalog_verified: false` (Oracle Database, SQL Server) follow vendor documentation and were not exercised on a real install. MongoDB on Linux is presence-only (no honest version string in `mongod`; use `packages`). Container roots are not scanned by this module yet.

## Linux evidence chain

```text
socket → PID → process → exe → service → package → source → repo
```

Every listen socket has a complete chain **or** an explicit `gap`. APT origin is never invented as `local/dpkg`. Unknown origin stays `installed_from_repository: null`. UDP unbound listeners are included. Debian `/usr` merge twin paths are used for ownership.

## Windows evidence chain

```text
listen → PID → process → exe → service → ServiceDll? → PE → uninstall app?
build+UBR → cbs_packages → WUA missing + update_context → reboot bit
```

Incomplete ports get an explicit `gap`. PE Authenticode is read offline (`signature_status` / signer). CBS package state is primary. HotFix is secondary only. Reboot evidence is four separate flags (`reboot_pending_windows_update`, `reboot_pending_cbs`, `pending_file_rename_operations`, `pending_computer_rename`) plus OR aggregate `reboot_pending`.

## Old Windows (2008 R2 / 2012 R2)

- Module scripts need Windows PowerShell 3.0 or later. On PowerShell 1.x/2.x (Windows 7 / Server 2008 R2 without WMF 3.0+) every PowerShell-backed module fails with `PowerShell 3.0 or later required (found 2.x; install WMF 3.0 or later)` instead of failing silently. Modules with a native Go path (for example the registry and toolhelp paths) still run.
- Without `Get-SmbServerConfiguration` (2008 R2), `security_configuration.smb.settings` reads `require_security_signature_server`, `enable_security_signature_server` and `enable_smb1_protocol` from `LanmanServer\Parameters` with `source: registry_fallback`. An absent value stays `null`; OS defaults are left to the consumer.
- Without `Get-TlsCipherSuite` (2012 R2 and older), `tls_schannel.cipher_suites` and `cipher_suites_count` are `null` and `cipher_suites_source` is `unavailable`.

## Modules present vs deferred

See the main [README.md](../README.md) module tables for the full step-by-step list.

### Deferred (later)

- Deep Windows GPO / policy precedence
- Collection depth modes (`fast` / `standard` / `deep`)
- Hyper-V / WSL / container network compartments
- Full-host language crawls (collector stays process-led + bounded roots)

## Evidence honesty

- Partial module failures set `collection.partial=true`.
- Permission gaps → `permission_denied` / incomplete chain, not fake success.
- Integrity: `validate` recomputes SHA-256 over the JSON-canonical payload.
