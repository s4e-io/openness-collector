# The `.openness` evidence file

What a `.openness` file contains, how records are shaped and how integrity is checked. Schema version: **1.6.0**.

[Back to README](../README.md)

## `.openness` file format

A `.openness` file is JSON.

### Envelope

| Field | Meaning |
|---|---|
| `schema_version` | Document schema (now `1.6.0`) |
| `collector` | Tool name, version, build id, osquery version |
| `collection` | Run id, times, privilege, status, partial flag |
| `asset` | Hostname, machine id, platform, arch |
| `modules` | Per-module results + evidence |
| `errors` | Aggregated errors |
| `integrity` | Hash algorithm + payload hash |

### Top-level inventories (merged from modules)

| Field | Typical source module |
|---|---|
| `operating_system` | `os_inventory` |
| `hardware` | `hardware_inventory` |
| `network` | `network_inventory` |
| `users` | `users` |
| `packages` | `packages` (Linux) |
| `applications` | `applications` (Windows) |
| `patches` | `patches` (Windows, secondary) |
| `missing_updates` | `missing_updates` (Windows) |
| `cbs_packages` | `cbs_packages` (Windows) |
| `update_context` | `missing_updates` |
| `services` | `services` |
| `processes` | `processes` |
| `listening_ports` | `listening_ports` |
| `features` | `windows_features` |
| `kernel` | `kernel_inventory` |
| `security_configuration` | `security_configuration` |
| `security_products` | `security_products` |
| `containers` | `containers` |
| `language_deps` | `language_deps` |
| `loaded_libraries` | `loaded_libraries` |
| `software_inventory` | Catalog-detected products (`software_instance`, `software_inventory_summary`), schema 1.5.0 |
| `evidence_chains` | `evidence_chain` |

## How evidence records are shaped

Each module returns many evidence records.

Typical record fields:

1. `evidence_id` - unique id
2. `source` - local source tag
3. `source_module` - module id
4. `observed_at` - UTC time
5. `value` - normalized object
6. `raw_value` - optional raw capture
7. `collection_status` - see below

### Allowed `collection_status` values

- `observed` - we saw it
- `permission_denied` - OS blocked us
- `unavailable` - tool/file missing
- `error` - unexpected failure
- `skipped` - intentionally not collected
- `partial` - some fields missing / truncated

### Module status values

- `success`
- `partial`
- `error`
- `unavailable`
- `permission_denied`

### Module limits and truncation

A module result can carry `truncated: true` (omitted when false). It means the module stopped at a record or size limit; the module status is `partial` and its `errors` say why:

| Error code | Module | Meaning |
|---|---|---|
| `package_limit_truncated` | `packages`, `containers` | Package records capped (20000 per host or container, 100000 across containers). Container records also get `packages_truncated: true` and `package_limit`. |
| `output_size_truncated` | any | The evidence file would have exceeded 256 MiB; the module with the most records was cut until it fit. |
| `timeout` | any | Module timeout or the global `--timeout` was reached. The module status is `error`; the run still writes the evidence collected so far with `collection.status=partial`. |
| `no_packages` | `packages` | No installed packages were read (status `unavailable`). An empty package list is never reported as `success`. |

### Container records

Each `containers` record describes one container. Fields added in `containers` 1.2.0 are optional; a consumer must accept records without them.

| Field | Meaning |
|---|---|
| `os_release` | OS identity of the image, read from `/etc/os-release`, else `/usr/lib/os-release`, in the container rootfs or copied out with `docker cp` / `podman cp`. Absent when neither file exists (scratch images) or could not be read. |
| `os_release.id` | `ID`, lower case (`debian`, `ubuntu`, `rocky`, `alpine`, ...). |
| `os_release.id_like` | `ID_LIKE`, lower case, space separated. |
| `os_release.name` | `NAME`. |
| `os_release.version_id` | `VERSION_ID` (`11`, `22.04`, `9.3`). |
| `os_release.version_codename` | `VERSION_CODENAME`, lower case (`bullseye`, `jammy`). |
| `os_release.pretty_name` | `PRETTY_NAME`. |
| `os_release.source` | `rootfs` or `runtime_cp`: how the file was read. |
| `os_release.source_file` | The path inside the container that was read. |

Keys missing from the file are left out. dpkg entries in a container's `packages` also carry `source_package` (the dpkg `Source` name, else the binary name) and `source_version` (the version in `Source: name (version)`, else null), like host packages.

### Relationship confidence labels

When we emit relationships, we label how strong the link is:

- `direct` - strong local proof
- `strong` - good proof with small inference
- `inferred` - best effort, clearly labeled

We do not hide inference.

### Remediation-oriented observation fields (schema 1.4.0)

Additive fields so S4E can build **action** cards without collector-side decisions:

| Field | Where | Meaning |
|-------|--------|---------|
| `highest_list_version` | Linux `packages` | Highest version for name/arch in `/var/lib/apt/lists` (not apt pin candidate) |
| `highest_list_origin` | Linux `packages` | `{origin,label,suite,component,url,esm}` for that list entry |
| `lists_updated_at` | Linux `packages` | Newest APT lists/InRelease file mtime (UTC; often mirror Last-Modified) |
| `apt_update_success_at` | Linux `packages` | `/var/lib/apt/periodic/update-success-stamp` mtime when present |
| `reboot_required` | Linux `os_inventory` / `kernel_inventory` | `/var/run/reboot-required` present |
| `reboot_required_packages` | same | Lines from `reboot-required.pkgs`, or `null` |
| `last_deployment_change_time` | Windows `missing_updates` | WUA `LastDeploymentChangeTime` (UTC; not MSRC publish date) |
| `is_downloaded` / `is_installed` / `msrc_severity` | Windows `missing_updates` | Pending-row flags (`is_installed` is always false for search hits) |
| `reboot_pending_windows_update` | Windows `os_inventory` / CBS context | WU `RebootRequired` key |
| `reboot_pending_cbs` | same | CBS `RebootPending` key |
| `pending_file_rename_operations` | same | Session Manager value present |
| `pending_computer_rename` | same | ActiveComputerName ≠ ComputerName |
| `reboot_pending` | same | OR of WU + CBS flags only (rename signals stay separate) |

## Integrity and validate

### How the hash is made

1. Temporarily clear integrity fields.
2. Marshal a canonical JSON payload.
3. SHA-256 hash that payload.
4. Store hex digest in `integrity.payload_hash`.
5. Set `integrity.algorithm = SHA-256`.

### What `validate` checks

1. File can be loaded (plain JSON or gzip).
2. Payload hash matches recomputation.
3. Collection / module / evidence status enums are allowed.
4. Relationship endpoints point to known entity ids.
5. Python entity/relationship types match the schema 1.4.0 allowlist.

Result:

- print `OK`, or
- print one `FAIL:` line per issue and exit non-zero

**File permissions:** if `collect` ran as root (e.g. `sudo collect`), run `validate` / `inspect` as root too, or collect to a path your user can read (for example `$HOME/host.openness`).

### What `inspect` prints

Short summary only:

- schema version
- hostname / machine id
- privilege
- status / partial
- module and inventory counts
- integrity hash
