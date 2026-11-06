# Changelog

All notable changes to this project are documented here.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Timeouts are hard. Every external command runs in its own process group bound to the collection deadline and the whole group is killed on cancel, so a hung helper (for example `rpm --root` inside a container rootfs) can no longer keep the collector waiting. `--timeout` is a global deadline: modules that do not return in time are recorded with error code `timeout`, modules not started yet are recorded the same way, and the evidence collected so far is written as `partial`.
- `packages` reads distroless Debian `/var/lib/dpkg/status.d/*` on the host, and `containers` reads it in container roots and through `docker cp`.
- Container package lists were capped at 500 and the `docker cp` fallback dropped the truncation record. The cap is now 20000 per container and a cut is always recorded (`package_limit_truncated`, `packages_truncated`, `package_limit`).
- A very large package database no longer exhausts memory or fails at write time. Package databases are streamed, collection stops at the record cap and is marked partial, and if the evidence file would still exceed its size limit the largest module is cut (`output_size_truncated`) instead of writing nothing.
- Runtime errors print only the error, not the full usage text. Flag errors still print usage.

### Added

- `containers` 1.2.0: each container record carries `os_release` (`id`, `id_like`, `name`, `version_id`, `version_codename`, `pretty_name`, `source`, `source_file`) from the image's `/etc/os-release` or `/usr/lib/os-release`, read from the rootfs or through `docker cp` / `podman cp`, so a resolver can select vendor rules for Debian, Ubuntu and RPM-based images. Container dpkg entries also carry `source_package` and `source_version`. Both are additive and optional. See `docs/EVIDENCE.md`.

- `containers` 1.3.0: a container whose package database is present but could not be read (rpm timeout or error, no `rpm` on the host, unreadable dpkg or apk data) carries `packages_error` (`code`, `message`), and the module error uses code `container_packages_unread` instead of `partial`, so a consumer can tell unread packages from an image without a package database. Additive and optional. See `docs/EVIDENCE.md`.

### Changed

- `packages` 1.5.0: zero packages is reported as status `unavailable` with error code `no_packages`, also when a package database exists but is empty. Module results can carry `truncated: true`. See `docs/EVIDENCE.md`.

## [0.8.0] - 2026-11-04

### Changed

- **Breaking for downloaders:** the tool is now called `openness-collector`. The command (`openness-collector --help`), `go install` path (`./cmd/openness-collector`), `scripts/build.sh` output and the release assets are `openness-collector_<version>_<os>_<arch>` (`.exe` on Windows) instead of `openness_<version>_...`. `version` prints `openness-collector <version> schema=<schema>`. The evidence field `collector.name` stays `openness`, and saved credentials stay in `~/.config/openness/`.

### Added

- `tools/hostcheck`: end-to-end checker that runs every command on a real host and compares the evidence with the host's own tools. New CI jobs run it on `ubuntu-latest`, `windows-latest` and in containers of Ubuntu 20.04/22.04/24.04, Debian 12, Rocky 9, Alma 9, Amazon Linux 2023, openSUSE Leap 15 and Alpine 3.20.
- README doc drift test: `go test ./internal/cli` fails when a command, flag or flag default in code is missing from the README Usage section.

### Documentation

- README restructured for users: install, quick start, and a Usage section with every command and flag. Design and internal material moved unchanged to `docs/DESIGN.md`, `docs/EVIDENCE.md`, `docs/MODULES.md` and `docs/DEVELOPMENT.md`. Feed sync details are left to the openness-resolver README.
- `docs/KNOWN_LIMITATIONS.md` collector version updated to 0.7.1 (the CI lint step failed on it).

- README for users of a release: install from the release (checksums, cosign verify), release asset names next to the built ones, scanning a running container (`docker cp` + `docker exec`) and a remote host over SSH, why `status: partial` is normal in a container, and the next step with openness-resolver installed as `openness-resolver`.

## [0.7.1] - 2026-11-03

### Fixed

- The `VERSION` file still said 0.6.0, so the v0.7.0 release did not run; 0.7.1 is 0.7.0 with the version files in step.

## [0.7.0] - 2026-11-03

### Added

- Windows `applications` **1.4.0**: each Add/Remove Programs entry carries `key` (the Uninstall subkey name), `view` (`HKLM64`, `HKLM32`, `HKCU`) and `display_icon`; per-user entries also carry `product_code`.
- `collect --file-probes`: files a consumer's application catalog wants checked to confirm a match (a renamed program cannot pass for a product by its name). Each probe names the applications it applies to (`name`, `publisher` regular expressions, case-insensitive) and one file relative to `install_location`, `program_files` or `display_icon_dir`; only the files of matching applications are looked at, at most 300 per run, all in one PowerShell call. The application gets `file_checks[]`: `probe_id`, `base`, `path`, `exists`, `file_version` (VS_FIXEDFILEINFO), `file_version_string`, `product_version`, `signature_status` (`valid`, `not_signed`, `invalid`, `not_trusted`, ...), `signer_subject`, `signer_cn`, `error`. A file that cannot be read is an entry with `error`, never a module error. Same argument forms as `--registry-values` (base64url JSON or `@<file>`).

## [0.6.0] - 2026-11-02

### Added

- `.openness` schema version **1.6.0**: `security_configuration.registry` (Windows).
- Windows `security_configuration` **1.4.0**: `registry` list with one object per requested HKLM value (`key`, `name`, `hive`, `present`, `type`, `value`, optional `pattern` / `error`). The built-in table (`internal/modules/windows/security_registry.go`) covers LSA, WDigest, speculative execution, DLL search, LLMNR, NetBIOS (per interface), PrintNightmare, Netlogon, LDAP signing/channel binding, IE user32 hardening, autorun, UAC, CredSSP, SMB signing/SMB1/null sessions, Schannel protocols/ciphers/hashes/DH, .NET strong crypto, Winlogon, WinRM, RDP and Spooler. Reads are read-only through .NET (`/` in Schannel cipher names is safe). Secrets (Winlogon `DefaultPassword` and similar) are presence-only. The list is passed to PowerShell through a temp file.
- `collect --registry-values`: extra HKLM values at run time, base64url JSON array or `@<file>`; HKLM only, max 1000 entries, inline argument max 7000 characters.
- Windows `security_configuration`: SMB server signing / SMB1 from `LanmanServer\Parameters` (`source: registry_fallback`) when `Get-SmbServerConfiguration` is missing (2008 R2).
- `packages` **1.4.0**: Alpine host packages from `/lib/apk/db/installed` (file parse, no `apk` binary), with the apk origin as `source_package`. The apk database parser is shared with container scanning, which now also tolerates CRLF and trailing whitespace.

### Changed

- License changed from the PolyForm Noncommercial License 1.0.0 to the [Apache License, Version 2.0](LICENSE). Openness is open source; COMMERCIAL.md is removed. Releases published before this change keep the license they were published under.
- Windows `security_configuration`: when `Get-TlsCipherSuite` is missing or fails (2012 R2 and older), `tls_schannel.cipher_suites` and `cipher_suites_count` are `null` instead of `[]` / `0`, so "not collected" does not read as "no suites".
- Windows PowerShell modules now fail with `PowerShell 3.0 or later required` on PowerShell 1.x/2.x instead of failing with a bare exit status or returning empty output.

## [0.5.0] - 2026-10-28

### Changed

- License changed from MIT to the [PolyForm Noncommercial License 1.0.0](LICENSE). The project is now source-available: free for non-commercial use, commercial use is reserved to S4E (see [COMMERCIAL.md](COMMERCIAL.md)). Releases published before this change keep the license they were published under.

### Fixed

- `asset.asset_id` was a new random value on every run, so the same host got a new id (and the resolver new finding ids) on each collection. It is now derived from the OS machine id (`/etc/machine-id`, `MachineGuid`, `IOPlatformUUID`); a host without one keeps a random id. `collection_id` stays the per-run id. Cloned images that share a machine id share an asset id.
- `software_inventory` attached every listening catalog port to every instance of the product, so a stopped install or another server on port 80 looked exposed. A port is now attributed only when one of the instance's own processes owns the listening socket (Linux socket inode to pid, Windows `GetExtendedTcpTable` owner pid, IPv4 and IPv6). Without root, Linux sockets of other users have no known owner and are not attributed.

- `packages` ran `rpm -qa` on any host with the rpm tool. On dpkg hosts rpm has no system database and falls back to `~/.rpmdb`, writing SQLite WAL/SHM files under root's home. It now runs only when a system rpm database exists (`/var/lib/rpm`, `/usr/lib/sysimage/rpm`).

### Added

- `.openness` schema version **1.5.0**: top-level `software_inventory` section.
- `software_inventory` **1.0.0** (Linux + Windows, `internal/modules/swinv`): catalog-driven detection of Oracle Database, PostgreSQL, MySQL, MariaDB, SQL Server, Redis, MongoDB, nginx, Apache httpd, Tomcat, OpenSSL, OpenSSH and Java runtimes. Versions are read from files, jars and registry only (`file_regex`, `zip_entry_regex`, `dir_names`, `registry_value`, `pe_version`); no product binary is executed. Each instance records `version_source`, all `version_candidates`, `patch_ids` (Oracle oneoffs), signals and `confidence`; unreadable versions stay `null` with `gap`. Catalog entries carry `verified` provenance; unverified entries are flagged on the instance.
- CI `smoke` job: runs a full `collect` on ubuntu/windows/macos runners and prints per-module durations and detected software (no evidence file is uploaded).
- Windows `windows_features` **1.1.0**: native Server Manager component-cache fast path (`source: servermanager_component_cache`) plus a 45 s own deadline for the DISM cmdlets (`FEATURE_API_TIMEOUT`, `windows_features_context` row). The smoke run showed `Get-WindowsOptionalFeature` consuming the full 180 s module budget on a busy CBS.

### Fixed

- Review follow-ups: Schannel registry-only TLS observation; Windows language_deps validator; OS inventory CIM merge / no invented `version_id`; WUA unresolved supersede KB = null + scope; remediation field naming (see 0.5.0 notes).
- `readRebootRequired` owns Debian-family gating (kernel_inventory no longer invents `false` on RHEL).
- language_deps `entity_id` stable without version; WUA `supersedes_kb_partial`; registry-only OS `version` null (not CurrentVersion 6.3).
- gofmt across tree.

### Changed (oss readiness)

- Go toolchain **1.26.10** (clears govulncheck stdlib findings; govulncheck is now a hard CI gate). Was 1.25.1 for the macOS LC_UUID fix.
- Windows CI hermetic: stub OS inventory PS; skip Unix-path python fixtures; ACL-aware credentials mode check.
- Services `path_name` / `binary_path` pass through `RedactSecrets`.
- Removed `apt-cache` execution from evidence_chain; README/KNOWN_LIMITATIONS list real host commands (incl. `powershell.exe`).
- Dropped lab scripts that used `sshpass -p` / `StrictHostKeyChecking=no`; deleted `lab-bridge-tmp-*` tags.
- Token resolution also accepts `S4E_API_TOKEN`; README warns against `--token` on argv.
- Service `path_name` / ImagePath redacted via `RedactSecrets`; schema docs → 1.4.0; test hostname `TESTHOST`.
- language_deps stable ids: Python uses site-packages root; NuGet uses package folder (not versioned dirs).
- CI: gofmt/vet/govulncheck, schema consistency, matrix test on ubuntu/windows/macos, action SHA pins, Dependabot.
- Added CODE_OF_CONDUCT.md, CODEOWNERS, NOTICE (third-party licenses).
- CI builds Windows amd64 and darwin arm64 in addition to Linux; README/`VERSION` consistency check.
- Release workflow publishes Windows amd64 + darwin arm64 binaries, `SHA256SUMS`, and keyless cosign signatures of the checksum file.
- Cosign CLI pinned (`v2.4.3`); CI runs `verify-blob` after sign; README documents identity/issuer for consumers.

### Added

- `.openness` schema version **1.4.0**.
- Linux `packages` **1.3.0**: highest-in-lists version observation + origin + lists freshness stamp (see field names in README; not apt-cache "candidate").
- Linux `os_inventory` / `kernel_inventory`: reboot-required marker + pkgs list.
- Windows `os_inventory` **1.2.0**: three-tier / merge fallback + identity normalize; reboot signal flags.
- Windows `missing_updates` **1.3.0**: WUA supersedence graph + deployment change time; pending `is_installed=false`, `is_downloaded`, `msrc_severity`.
- Windows `security_configuration` **1.3.0**: Schannel registry observation (`enabled_registry` / `disabled_by_default` / `key_present`), indexed cipher suites, curl meta, WinTrust padding-check (null when absent).
- Windows `applications` **1.3.0**: NDP `release_dword` + Framework64 numeric file versions (`source_type`/`path`).
- Windows `language_deps` **1.0.0**: file-only language identity (no interpreter/package-manager execution).

### Notes

- Remediations/actions are **not** computed in the collector.
- `supersedes_kb_article_ids` null ≠ empty list; scope is `pending_set_only`.
- Batch-1 toward action cards: L1, L2, W1, W4, W6. Later: L3–L6, W2, W3, W5.

## [0.4.9] - 2026-10-14

### Changed

- Release cut after Linux OS inventory fallback work (`lsb-release` / `dpkg` status).

## [0.4.8] - 2026-09-20

### Added

- API token login and gzip upload path for S4E ingest (`feat(auth)`).

## [0.4.7] - 2026-08-10

### Added

- Initial public release under MIT License
- CLI: `collect`, `validate`, `inspect`, `upload`, `version`, `modules`, `self-test`
- Linux evidence modules (packages, kernel, containers, Python envs, network, users, and related collectors)
- Windows evidence modules (features, applications, security products, evidence chain)
- `.openness` schema version **1.3.4**
- Secret redaction in cmdline and sensitive fields
- Cross-platform build scripts and GitHub Actions CI/release (Linux binaries)
- Documentation: README, `docs/KNOWN_LIMITATIONS.md`, `docs/CREDS.example.md`

### Notes

- CVE matching and vulnerability decisions belong in [openness-resolver](https://github.com/s4e-io/openness-resolver), not this repo.
- Project hub: [github.com/s4e-io/openness](https://github.com/s4e-io/openness)

[0.6.0]: https://github.com/s4e-io/openness-collector/releases/tag/v0.6.0
[0.5.0]: https://github.com/s4e-io/openness-collector/releases/tag/v0.5.0
[0.4.9]: https://github.com/s4e-io/openness-collector/releases/tag/v0.4.9
[0.4.8]: https://github.com/s4e-io/openness-collector/releases/tag/v0.4.8
[0.4.7]: https://github.com/s4e-io/openness-collector/releases/tag/v0.4.7
