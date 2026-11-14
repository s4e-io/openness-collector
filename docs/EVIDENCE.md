# The `.openness` evidence file

What a `.openness` file contains, how records are shaped and how integrity is checked. Schema version: **1.7.0**.

[Back to README](../README.md)

## `.openness` file format

A `.openness` file is JSON.

### Envelope

| Field | Meaning |
|---|---|
| `schema_version` | Document schema (now `1.7.0`) |
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
| `container_packages_unread` | `containers` | A container has a package database that could not be read (message `<container id>: <code>[: detail]`). The container record carries `packages_error`. The module status is `partial`. |

### Container records

Each `containers` record describes one container. Fields added in `containers` 1.2.0 and later are optional; a consumer must accept records without them.

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
| `packages_error` | Added in `containers` 1.3.0. Present when the container has a package database (rpm, dpkg or apk) that could not be read, so its packages are unknown rather than empty. Absent for images without a package database (scratch, distroless without dpkg data). |
| `packages_error.code` | `rpm_timeout` (`rpm --root` did not finish before the deadline), `rpm_unavailable` (rpm database present, no `rpm` tool on the host), `package_read_failed` (the tool exited with an error, or a database file could not be opened or parsed). |
| `packages_error.message` | Short human readable reason. |

Keys missing from the file are left out. dpkg entries in a container's `packages` also carry `source_package` (the dpkg `Source` name, else the binary name) and `source_version` (the version in `Source: name (version)`, else null), like host packages.

### Relationship confidence labels

When we emit relationships, we label how strong the link is:

- `direct` - strong local proof
- `strong` - good proof with small inference
- `inferred` - best effort, clearly labeled

We do not hide inference.

### Package origin and file ownership (schema 1.7.0)

Two facts with the same shape on every package manager. The collector reports what it observed and does not classify an origin as "distribution" or "third party"; that decision belongs to the consumer.

**`origin`** on every host `packages` record:

```json
"origin": {
  "vendor": "Docker",
  "maintainer": "Containerd team <help@containerd.io>",
  "repository_url": "https://download.docker.com/linux/ubuntu",
  "signing_key_id": null,
  "basis": ["apt_release_origin", "dpkg_maintainer"]
}
```

| Field | dpkg | rpm | apk |
|-------|------|-----|-----|
| `vendor` | Release `Origin` (else `Label`) of the apt list the installed version matched | `%{VENDOR}` | not recorded |
| `maintainer` | `Maintainer` | `%{PACKAGER}` | `m:` |
| `repository_url` | URL of the matched apt list | not recorded | not recorded |
| `signing_key_id` | not recorded | key id of the package signature, lower case | not recorded |

A field that was not observed is `null`, and `basis` lists only the observations that were made (`apt_release_origin`, `dpkg_maintainer`, `rpm_vendor`, `rpm_packager`, `rpm_signature`, `apk_maintainer`). rpm prints `(none)` for an unset tag; `origin` turns that into `null`. A dpkg package whose installed version is not in the apt lists still carries `maintainer`. Packages from vendor rpm repositories often have neither `Vendor` nor `Packager`; the signing key is then the only origin fact.

**`owner_package`** and **`owner_package_status`** on every `software_instance`:

| `owner_package_status` | Meaning |
|------------------------|---------|
| `owned` | A package owns one of the instance's files; `owner_package` is `{manager,name,version,architecture,entity_id,path}` |
| `not_owned` | The package databases were read and none owns the instance's files; `owner_package` is `null` |
| `not_checked` | No package database on the host (or not Linux), or the instance has no regular file to ask about; `owner_package` is `null` |

`entity_id` equals the entity id of the same package in `packages`, or `null` when version or architecture could not be read. Only regular files are asked about (path signals and process executables), because packages share directories. The summary record lists the databases that were read in `owner_managers`.

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
