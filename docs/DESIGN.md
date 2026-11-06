# Collector design

How the collector runs, the rules it follows when it decides a field, and how the evidence chains are proven. For the file format see [EVIDENCE.md](EVIDENCE.md); for each module see [MODULES.md](MODULES.md).

[Back to README](../README.md)

## Full collect pipeline (every step)

This is the exact engine flow in `internal/collect/engine.go`.

### Step A: Start

1. Read CLI flags / config.
2. Create an engine with options.
3. Detect OS (`linux` / `windows` / other).
4. Optionally locate `osqueryi`.

### Step B: Register modules

**On Linux, register:**

1. `os_inventory`
2. `hardware_inventory`
3. `packages`
4. `kernel_inventory`
5. `services`
6. `processes`
7. `listening_ports`
8. `evidence_chain`
9. `loaded_libraries`
10. `containers`
11. `language_deps`
12. `security_configuration`
13. `users`
14. `network_inventory`
15. `software_inventory`

**On Windows, register:**

1. `os_inventory`
2. `hardware_inventory`
3. `applications`
4. `windows_features`
5. `cbs_packages`
6. `patches`
7. `missing_updates`
8. `language_deps`
9. `services`
10. `processes`
11. `listening_ports`
12. `evidence_chain`
13. `security_products`
14. `security_configuration`
15. `users`
16. `network_inventory`
17. `software_inventory`

`openness-collector modules` prints the list for the current OS.

**On other OS:** only optional osquery hardware pack if osquery exists.

### Step C: Select modules

1. Apply `--exclude-modules` denylist.
2. Apply `--modules` allowlist (if set).
3. Skip modules that do not support the current OS.

### Step D: Create empty document

1. Set `schema_version`.
2. Set collector name/version/build id.
3. Create `collection_id`.
4. Set `execution_mode=local`.
5. Detect privilege level (`root` / `admin` / `user`).
6. Fill asset hostname / platform / architecture.
7. Start with `status=complete` and `partial=false`.

### Step E: Run each module

For every selected module:

1. Create a context with the module timeout.
2. Call `module.Run(ctx)`.
3. Optionally force-fail the module (test harness).
4. Optionally strip `raw_value` fields.
5. Append the module result to `document.modules`.
6. Merge evidence into top-level arrays/objects.
7. If module status is not `success`, mark collection partial and copy errors.

### Step F: Finish document

1. Set `completed_at` and `duration_ms`.
2. If any module failed/partial → `collection.status=partial`.
3. Else keep `collection.status=complete`.

### Step G: Write `.openness`

1. Compute SHA-256 over the JSON-canonical payload (integrity field zeroed during hash).
2. Set `integrity.algorithm=SHA-256` and `integrity.payload_hash`.
3. Marshal JSON with indent.
4. Optionally gzip.
5. Write to a temp file, chmod `0640`, rename into place.

### Step H: Optional upload

1. Read API key from the env var.
2. POST the file.
3. Retry on some 5xx / 429 responses.
4. HTTPS is required unless insecure upload is allowed.

## Honesty rules (how we analyze / decide fields)

These rules apply across modules.

1. **Observe, do not judge.** We record facts. We do not say “vulnerable”.
2. **Unknown is `null`.** Example: APT origin unknown → `installed_from_repository: null`, not `false`.
3. **Missing hop = gap.** Incomplete chains set `complete=false` and a `gap` string.
4. **No fake hops.** We never invent PID, package owner, or repo.
5. **Permission failure is explicit.** We do not convert denial into empty success.
6. **Caps are honest.** If we hit record limits, we mark `partial` and log why.
7. **Cmdline redaction.** Linux redacts password/token-like args and credential URLs when possible.
8. **Root helps, but is not magic.** Some kernel/protected objects still stay unresolved.
9. **`complete` ≠ “full OS coverage”.** It only means selected modules finished without reported errors.
10. **Resolver-ready IDs.** Entity ids and relationship endpoints must resolve (validated in schema 1.4.0+).

## Linux evidence chain (listen → package → repo)

Module: `evidence_chain` `1.0.0`

This is the main “how do we analyze a listening service?” pipeline.

### Chain goal

```text
socket → PID → process → exe → service → package → source package → repository
```

### Steps for each listening socket

1. **Start from socket**  
   Take protocol, address, port, inode, and owning PID from listen inventory.

2. **Resolve process**  
   Open `/proc/<pid>/`.  
   If PID is gone → gap `process_exited` (or similar).  
   If access denied → gap `permission_denied`.

3. **Resolve executable**  
   Read `/proc/<pid>/exe` and realpath.  
   If path missing → gap `process_path_unavailable`.

4. **Hash binary (capped)**  
   Compute file hash for a limited number of binaries.

5. **Find package owner**  
   Use dpkg ownership helpers.  
   Try original path, realpath, and `/usr` merge twin paths.  
   If no owner → gap `binary_not_package_owned`.

6. **Find source package**  
   Read package metadata `Source` when present.

7. **Find repository origin**  
   Use APT policy / lists enrichment.  
   Only emit `package_installed_from_repository` when origin is proven `true`.  
   If unknown → keep `null`.

8. **Find service unit**  
   Map MainPID / unit ownership when systemd knows the PID.

9. **Emit chain object**  
   Include:
   - `chain[]` hop names
   - `complete` boolean
   - `gap` string when incomplete
   - nested socket / process / binary / package objects
   - `relationships[]`

### Relationships emitted (when proven)

1. `process_listens_on_socket`
2. `process_executed_binary`
3. `binary_owned_by_package`
4. `package_built_from_source_package`
5. `package_installed_from_repository` (only if true)
6. `process_belongs_to_service`

### Example gap values

- `owning_pid_unavailable`
- `permission_denied`
- `process_exited`
- `process_path_unavailable`
- `binary_not_package_owned`

---

## Windows evidence chain (listen → PE → app)

Module: `evidence_chain` `1.1.0`

### Chain goal

```text
listen → PID → process → exe → service → ServiceDll? → PE metadata → uninstall app?
```

### Steps for each listener

1. Start from TCP/UDP listen inventory.
2. Resolve owning PID.
3. Resolve process image path.
4. If path is kernel/protected → gap such as `kernel_owned_socket`.
5. Map service that owns the process when possible.
6. Read `ServiceDll` for svchost-style services.
7. Read PE metadata (FileVersionInfo).
8. Read Authenticode signature status offline.
9. Hash binary paths with a cap.
10. Try to match uninstall app by install location prefix.
11. Emit `complete=true` only if required hops exist.
12. Otherwise emit `complete=false` + explicit `gap`.

We record signature status.  
We do not turn signature status into a CVE decision.

---

## Python inventory (how load is proven)

Module: `language_deps` `1.1.3` (Python path in `python_envs.go`)

This section is important.  
Many tools confuse “installed” with “loaded”.  
We keep them separate.

### Step 1: Find Python processes

1. Walk process seeds from `/proc`.
2. Detect Python by argv0 / cmdline (including busybox symlink cases).
3. Capture PID and interpreter path.

### Step 2: Discover environments

Possible environment sources:

1. Active process environment / prefix
2. `pyvenv.cfg` venv roots
3. Conda-like prefixes
4. System dist-packages / site-packages
5. Bounded known locations (not full-disk crawl)

Emit entities:

- `python_interpreter`
- `python_environment`
- `python_distribution`
- `python_inventory_coverage`

### Step 3: Inventory distributions

For each environment:

1. Scan `*.dist-info` / `*.egg-info` metadata (bounded).
2. Read name + version from METADATA.
3. Read installer when present (`pip`, etc.).
4. Record discovery method and paths.

### Step 4: OS ownership of distributions

We build a dpkg ownership index:

1. Read package list via `dpkg-query -W`.
2. Read file lists from `/var/lib/dpkg/info/*.list`.
3. Map distribution metadata files to owning binary packages.

Then set:

- `installation_origin` (`os_package`, `pip`, `conda`, `unknown`, …)
- `ownership_confidence` (`direct`, `none`, `inferred_path_unconfirmed`)
- relationship `python_distribution_belongs_to_os_package` only with file-list proof
- target package id form: `pkg:dpkg:<name>:<arch>:<raw_version>`

### Step 5: Active environment vs loaded code

Membership in an active environment only means:

- the distribution is present in an environment used by a process

It does **not** mean the code is loaded in memory.

So default runtime status stays:

- `installed_not_proven_loaded`

### Step 6: Confirmed load (strict)

A distribution becomes `confirmed_loaded` only when **all** of these are true:

1. `/proc/<pid>/maps` shows a **`.so`** path.
2. That `.so` path is under Python package path patterns (dist-packages / site-packages / `/lib/python…`).
3. dpkg file ownership maps that `.so` to an OS package.
4. That OS package maps to exactly one inventoried Python distribution.

Then we set:

- `runtime_load_status.status = confirmed_loaded`
- `runtime_detection_method = proc_maps_dpkg_ownership`
- relationship `process_loads_python_distribution`

### Step 7: What is never enough for load proof

1. “Package exists in site-packages.”
2. “Process uses that venv.”
3. “Many packages share the same site-packages directory.”
4. Path-prefix matching against a shared root without `.so` ownership.

Shared site-packages roots are never treated as load evidence.

### Step 8: Process relationships

Even when interpreter/environment entities are deduplicated:

1. We still emit per-PID `process_uses_python_interpreter`.
2. We still emit per-PID `process_uses_python_environment`.
3. `process_ids` accumulates all PIDs that used the entity.

### Allowed Python relationship types

1. `process_uses_python_interpreter`
2. `process_uses_python_environment`
3. `process_loads_python_distribution`
4. `python_environment_contains_distribution`
5. `python_interpreter_belongs_to_os_package`
6. `python_distribution_belongs_to_os_package`

---

## Other language deps (Node / Java / Go)

Still inside `language_deps`.

### Node

1. Find Node processes.
2. Locate app roots / `package.json`.
3. Read direct `node_modules` metadata with caps.
4. Emit `node_application` / `node_package`.

### Java

1. Find Java processes.
2. Parse classpath / JAR references.
3. Read JAR metadata with nested JAR caps.
4. Emit `java_application` / `java_archive`.

### Go

1. Find Go binaries from process exe.
2. Read `debug/buildinfo` only.
3. Emit `go_binary`.
4. Never invent versions from filenames.

### Global language honesty

1. Process-led discovery first.
2. Bounded known roots second.
3. No full filesystem crawl.
4. No package-manager execution (`pip`, `npm`, etc.).

---

## Containers

Module: `containers` `1.1.0`

### Steps

1. Detect runtime CLIs: Docker, Podman, nerdctl, fallback `ctr`.
2. List containers (`ps -a` style).
3. Inspect each container for image, digest, state, rootfs/MergedDir.
4. Prefer immutable image digest when available.
5. Read package DB from host-visible rootfs when possible.
6. Or copy package DB files read-only when needed.
7. Emit container entity + nested packages. The dpkg `status` file, distroless `status.d/*`, apk `installed` and `rpm --root` are read, at most 20000 package records per container and 100000 across all containers. When the cap cuts a container's list, the container record gets `packages_truncated: true` and `package_limit: <n>`, and the module gets `truncated: true` plus an error with code `package_limit_truncated`, whichever path (`rootfs` or `runtime_cp`) produced the packages.
8. Emit `container_uses_image` when image identity exists.

### Never

1. Never start a stopped container to inspect it.
2. Never exec a shell inside a container for mutation.
3. Never claim package inventory if the DB cannot be read.

Permission problems → `permission_denied`.

---

## Loaded libraries

Module: `loaded_libraries` `1.0.0`

### Steps

1. Take listening PIDs (interesting network-facing processes).
2. Read `/proc/<pid>/maps`.
3. Extract mapped `.so` paths.
4. Resolve package owner for each library path.
5. Emit `process_libraries` rows.
6. Emit `process_loads_libraries`.

### Caps

- Max PIDs processed (about 40)
- Max libraries per PID (about 80)

Over cap → partial + explicit reason.
