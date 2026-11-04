# Development context for AI assistants

Use this file when working on **openness-collector** with Cursor, Claude, Copilot, or similar tools.  
Paste the sections below into a chat so the assistant understands the project before writing code.

**Repo:** https://github.com/s4e-io/openness-collector  
**Sibling:** https://github.com/s4e-io/openness-resolver  
**License: Apache License 2.0 (open source, developed and maintained by S4E)

---

## Project purpose

**Openness** splits endpoint security into two deterministic steps:

1. **Collector (this repo)**, gather facts from the local machine.
2. **Resolver (separate repo)**, compare facts to vendor advisories and emit findings.

This repo answers: *“What is installed and running on this host, with proof?”*  
It does **not** answer: *“Is this CVE exploitable here?”*, that is the resolver’s job.

Design goals:

- **Deterministic**, same host state → same `.openness` file (modulo timestamps).
- **Honest**, unknown data stays unknown; gaps are explicit, never invented.
- **Offline-first**, collect once, validate and inspect without network.
- **Resolver-ready**, entity IDs, evidence chains, and source-package mapping so the resolver does not guess.

**Runtime: no AI.** LLMs may help write code; the collector binary never calls them.

---

## End-to-end pipeline (where this repo fits)

```
Host (Linux/Windows)
    │
    ▼
openness-collector  ──►  host.openness  ──►  openness-resolver  ──►  findings.json
   (this repo)            JSON evidence         (other repo)         vulnerable/fixed/…
```

---

## What this binary does (step by step)

1. Detect OS (`linux` / `windows` / limited `darwin`).
2. Register OS-specific modules (`internal/modules/linux`, `internal/modules/windows`).
3. Run each module with timeouts; collect evidence records.
4. Merge into one document (`internal/schema/document.go`).
5. Compute SHA-256 integrity hash over canonical JSON.
6. Write `.openness` file (`internal/evidencefile/writer.go`).
7. Optional: `validate`, `inspect`, `upload`.

Engine entry: `internal/collect/engine.go`  
CLI entry: `cmd/openness-collector/main.go`

---

## What this binary never does

- CVE / OVAL matching, risk scoring, remote scanning from inside the binary
- Installing packages, restarting services, accepting EULAs
- Running `pip` / `npm` / interpreters to “discover” packages
- Inventing APT repository origin or marking evidence chains complete when a hop is missing
- Treating “file exists under site-packages” as proof Python loaded a package

If data is missing → `null`, gap flag, or `partial` status. See README §2 and `docs/KNOWN_LIMITATIONS.md`.

---

## `.openness` format (schema 1.6.0)

Top-level sections (see `internal/schema/document.go`):

| Section | Purpose |
|---------|---------|
| `schema_version` | Currently `1.6.0` |
| `collector` | Name `openness`, version, build id |
| `collection` | `collection_id`, status, duration, privilege level |
| `software_inventory` | Catalog-detected products (`software_instance`), 1.5.0+ |
| `asset` | Hostname, platform, architecture |
| `operating_system` | Distro id/version (e.g. ubuntu jammy) |
| `packages[]` | Installed packages + source mapping |
| `processes[]`, `listening_ports[]` | Runtime state |
| `evidence_chains[]` | listen → binary → package links |
| `containers[]` | Image digests + inner package lists |
| `language_deps[]` | Python envs/distributions with load proof |
| `integrity` | SHA-256 over canonical payload |

Schema changes require bumping `SchemaVersion` and updating README + CHANGELOG.

---

## Linux modules (registered in engine)

| Module | Role |
|--------|------|
| `os_inventory` | `/etc/os-release`, kernel, machine id |
| `hardware_inventory` | CPU, memory, disks |
| `packages` | dpkg/apk installed packages |
| `kernel_inventory` | Running kernel details |
| `services`, `processes`, `listening_ports` | Runtime |
| `evidence_chain` | Port → process → binary → package |
| `loaded_libraries` | Mapped libs per process |
| `containers` | Docker/containerd images |
| `language_deps` | Python (+ Node/Java/Go signals) |
| `security_configuration`, `users`, `network_inventory` | Hardening / identity / network |

Windows: separate module set under `internal/modules/windows/` (applications, CBS, patches, PE chain, etc.).

---

## Honesty rules (do not break these in PRs)

From README §9, summary:

- Only record what was **read** from the system, not inferred CVE impact.
- Evidence chains list explicit hops; a missing hop → incomplete chain.
- Python: require load proof (interpreter + import path + process linkage), not directory presence alone.
- Redact secrets in cmdlines and configs (`internal/modules/linux/redact.go`).
- Partial module failure → document stays `partial=true` with reasons.

---

## Key paths

| Topic | Path |
|-------|------|
| CLI | `cmd/openness-collector/main.go` |
| Collect engine | `internal/collect/engine.go` |
| Schema | `internal/schema/document.go` |
| Writer + validate | `internal/evidencefile/writer.go` |
| Linux modules | `internal/modules/linux/` |
| Windows modules | `internal/modules/windows/` |
| Config | `config.example.yaml`, `internal/config/` |
| Upload | `internal/upload/` |
| Version | `VERSION`, `internal/version/version.go` |

---

## Build & test

```bash
go test ./...
bash scripts/build.sh          # dist/openness-collector_<version>_{linux_amd64,linux_arm64,darwin_arm64,windows_amd64.exe}
go run ./cmd/openness-collector self-test
```

Release: tag `vX.Y.Z` → GitHub Actions publishes Linux binaries.

---

## Copy-paste prompts

### Onboard an AI to this repo

```
You are helping develop openness-collector (github.com/s4e-io/openness-collector).

Purpose: collect deterministic local host evidence into host.openness JSON.
Non-goals: no CVE matching, no AI at runtime, no remote scanning.

Read README.md §1–2, §6–9 and docs/KNOWN_LIMITATIONS.md.
Summarize: collect pipeline, schema 1.5.0 sections, Linux module list, honesty rules.
Do not edit files yet.
```

### Implement a feature

```
Task: [describe change]

Repo: openness-collector
Constraints:
- Facts only; resolver decides vulnerability
- Honesty rules (README §9)
- Bump schema if .openness shape changes
- Add tests; run go test ./...
- No secrets or production .openness in commits

Propose plan, then minimal implementation.
```

### Fix a bug

```
Bug: [symptom]
Module/area: internal/modules/linux/[name] (or windows/schema/…)

Reproduce mentally from code, find root cause, add regression test, fix minimally.
Run go test ./...
```

### PR review

```
Review uncommitted changes in openness-collector.

Check: secrets committed, schema/version docs, redaction, honesty rules, tests.
List findings by severity. No commits.
```

---

## Human contact

- Bugs/features: https://github.com/s4e-io/openness-collector/issues
- Security: [SECURITY.md](../SECURITY.md)
- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Resolver (downstream): https://github.com/s4e-io/openness-resolver
