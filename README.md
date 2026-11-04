# OpenNess Vulnerability Scanner: Collector

`openness-collector` is the local endpoint evidence collector of OpenNess Vulnerability
Scanner. It reads the machine it runs on and writes one JSON evidence file (`.openness`)
with the operating system, packages, applications, updates, services, processes, listening
ports, users, security settings and the links between them.

**OpenNess Vulnerability Scanner:** [github.com/s4e-io/openness](https://github.com/s4e-io/openness)  
**This repo:** [github.com/s4e-io/openness-collector](https://github.com/s4e-io/openness-collector)

Version: **0.8.0**  
Schema: **1.6.0**  
License: [Apache License 2.0](LICENSE) (open source, developed and maintained by S4E)

The collector does **not** decide if something is vulnerable, does not match CVEs or OVAL,
and does not scan remote hosts. A separate tool,
[openness-resolver](https://github.com/s4e-io/openness-resolver), reads the `.openness`
file and finds the missing updates.

**Development note:** we use AI coding assistants while coding; the collector does **not**
use AI at runtime. Project purpose and technical context for contributors:
[docs/PROMPTS.md](docs/PROMPTS.md).

---

## Contents

- [What it does](#what-it-does)
- [What it never does](#what-it-never-does)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Config file](#config-file)
- [Upload (optional)](#upload-optional)
- [Supported platforms](#supported-platforms)
- [More documentation](#more-documentation)
- [Openness in S4E](#openness-in-s4e)
- [License](#license)

---

## What it does

1. You run one binary on the host (Linux or Windows).
2. The binary selects the modules for that OS (`openness-collector modules` lists them).
3. Each module reads local files, `/proc`, package databases or OS APIs.
4. The records are merged into one document with a SHA-256 integrity hash.
5. The document is written to a `.openness` file.
6. You can validate and inspect the file offline, and optionally upload it.

The goal is **deterministic evidence**: a later resolver should not need to guess missing
hops. If something is unknown, the field is `null`, missing, or marked with an explicit `gap`.

## What it never does

1. It never matches CVEs, OVAL, or vendor advisories, and never scores risk.
2. It never opens SSH or WinRM from inside the collector binary.
3. It never installs packages, updates, starts/stops services, or accepts EULAs.
4. It never runs language package managers or interpreters to *discover* packages (`pip`, `npm`, `python -c`, `node -v`, `go version`, ...). Windows `language_deps` is file/PE metadata only.
5. It never invents a repository origin when APT list data is missing.
6. It never marks a chain complete when a hop is missing.
7. It never treats "file is under site-packages" as proof that Python loaded a package.
8. It never crawls the whole filesystem for language packages.
9. It never needs network access. Upload is optional and off by default.

**Honest about what it *does* run:** the collector uses the host's own OS tools for
inventory. Package managers are used only for *read-only queries* (`dpkg-query`,
`rpm -qa` / `-qf`), never `apt-get` / `apt-cache`. On Windows, almost all modules shell out
to `powershell.exe`.

| OS | Commands (read-only inventory) |
|----|--------------------------------|
| Linux | `dpkg-query`, `rpm`, `systemctl`, `uname`, `ip` / `ifconfig`, `ssh -V`, `sudo --version`, `ufw`, `firewall-cmd`, `nft`, `iptables`, `ctr` / container runtime `ps`/`inspect`, `sshd -T`, `readlink` |
| Windows | `powershell.exe` (CIM, registry, WUA, services, PE metadata) |

APT *candidate-style* fields on packages come from parsing `/var/lib/apt/lists` (file mtime
+ `update-success-stamp`), never from `apt-cache policy`.

---

## Install

Root / Administrator is recommended for full evidence. Go is only needed to build from source.
`osqueryi` is optional and not required; native modules are primary.

### Release download (recommended)

Each [release](https://github.com/s4e-io/openness-collector/releases) has
`openness-collector_<version>_<os>_<arch>` binaries, `SHA256SUMS` and a keyless cosign
signature of it (`SHA256SUMS.sig`, `SHA256SUMS.pem`).

| OS / arch | Release asset |
|---|---|
| Linux amd64 | `openness-collector_<version>_linux_amd64` |
| Linux arm64 | `openness-collector_<version>_linux_arm64` |
| Windows amd64 | `openness-collector_<version>_windows_amd64.exe` |
| macOS Apple Silicon | `openness-collector_<version>_darwin_arm64` (CLI helpers only, no native modules) |

```bash
gh release download -R s4e-io/openness-collector -p 'openness-collector_*_linux_amd64' -p 'SHA256SUMS*'
# check the binary against the published checksums
sha256sum -c --ignore-missing SHA256SUMS      # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS
# optional: prove the checksums come from this repo's release workflow
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/s4e-io/openness-collector/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
install -m 0755 openness-collector_*_linux_amd64 /usr/local/bin/openness-collector
```

On Windows (PowerShell), compare the hash by hand:

```powershell
(Get-FileHash .\openness-collector_<version>_windows_amd64.exe -Algorithm SHA256).Hash.ToLower()
Select-String windows_amd64 .\SHA256SUMS
```

### go install

Needs Go (see `go.mod` for the version).

```bash
go install github.com/s4e-io/openness-collector/cmd/openness-collector@latest
```

### Build from source

```bash
git clone https://github.com/s4e-io/openness-collector
cd openness-collector
./scripts/build.sh            # writes dist/openness-collector_<version>_<os>_<arch>
# or one target:
CGO_ENABLED=0 go build -o openness-collector ./cmd/openness-collector
```

More build, test and release notes: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

---

## Quick start

The examples assume the binary is on `PATH` as `openness-collector`.

### Collect on Linux

```bash
sudo openness-collector collect --output ./host.openness
sudo openness-collector validate ./host.openness
sudo openness-collector inspect ./host.openness
```

`sudo collect` writes a **root-owned** file (mode `0640`). Run `validate` and `inspect` with
the same user, or collect into your home directory without sudo (less evidence):

```bash
openness-collector collect --output "$HOME/host.openness"
openness-collector validate "$HOME/host.openness"
```

### Collect on Windows

From an Administrator PowerShell:

```powershell
.\openness-collector.exe collect --output .\host.openness
.\openness-collector.exe validate .\host.openness
```

### Collect in Docker (works from macOS too)

```bash
mkdir -p out
# Apple Silicon -> linux_arm64; Intel/amd64 Docker host -> linux_amd64
docker run --rm \
  -v "$(pwd)/openness-collector_<version>_linux_arm64:/openness-collector:ro" \
  -v "$(pwd)/out:/out" \
  ubuntu:22.04 \
  /openness-collector collect --output /out/host.openness --module-timeout 180
```

To scan a container that is already running (here `web`), copy the binary in and the
evidence out:

```bash
docker cp openness-collector_<version>_linux_arm64 web:/tmp/openness-collector
docker exec -u 0 web sh -c 'chmod +x /tmp/openness-collector && /tmp/openness-collector collect --output /tmp/host.openness --module-timeout 180'
docker cp web:/tmp/host.openness ./host.openness
docker exec -u 0 web rm -f /tmp/openness-collector /tmp/host.openness
```

### Collect on a remote Linux host (SSH)

The binary never connects anywhere by itself. Copy it over, run it as root, bring the file back:

```bash
scp openness-collector_<version>_linux_amd64 admin@server:/tmp/openness-collector
ssh -t admin@server 'chmod +x /tmp/openness-collector && sudo /tmp/openness-collector collect --output /tmp/host.openness && sudo chown "$USER" /tmp/host.openness'
scp admin@server:/tmp/host.openness ./server.openness
ssh admin@server 'rm -f /tmp/openness-collector /tmp/host.openness'
```

### Read the result

**`status: partial` is normal in a container** (and on a stripped-down host): modules that
need systemd, listening-socket or network tools record that they could not run, and the
package inventory is still complete. `inspect` prints the summary; the reasons are in
`modules[].errors` of the file. The file format is described in
[docs/EVIDENCE.md](docs/EVIDENCE.md).

### Next: find the missing updates

Give the `.openness` file to
[openness-resolver](https://github.com/s4e-io/openness-resolver). Its README covers the
vulnerability data it uses and how to keep it up to date; the collector does not download
any feeds.

---

## Usage

```text
openness-collector <command> [flags]
```

| Command | What it does |
|---|---|
| [`collect`](#collect) | Run the modules for this OS and write a `.openness` file |
| [`validate`](#validate) | Re-check the integrity hash and status values of a file |
| [`inspect`](#inspect) | Print a short JSON summary of a file |
| [`upload`](#upload) | Send an existing file to an ingest API (optional) |
| [`login`](#login) | Save an API token for uploads (optional) |
| [`logout`](#logout) | Remove the saved API token |
| [`whoami`](#whoami) | Check the saved or environment API token |
| [`version`](#version) | Print the collector and schema version |
| [`modules`](#modules) | List the modules available on this OS |
| [`self-test`](#self-test) | Quick local collect + validate (`os_inventory` only) |

Every command accepts `-h`, `--help`. Exit status is `0` on success and `1` on any error.
Boolean flags take `--flag` for true and `--flag=false` for false.

### collect

Run the modules for the current OS and write the evidence file.

```bash
sudo openness-collector collect --output ./host.openness
```

#### Output

| Flag | Description | Example |
|---|---|---|
| `--output` | Path of the `.openness` file. Default: `./host.openness` (or `output.path` from `--config`). | `--output /tmp/web01.openness` |
| `--compress` | Gzip the file on disk; `.gz` is added to the name. Default: `false`. | `--compress` |
| `--keep-raw-evidence` | Keep the `raw_value` field of each record (raw lines as read). Default: `true`. | `--keep-raw-evidence=false` |
| `--build-id` | Free text stored as `collector.build_id` in the file. Default: empty. | `--build-id nightly-42` |

#### Scope

| Flag | Description | Example |
|---|---|---|
| `--modules` | Comma-separated allowlist of module ids. Default: every module for this OS (see `modules`). | `--modules os_inventory,packages` |
| `--exclude-modules` | Comma-separated denylist; applied before `--modules`. Default: empty. | `--exclude-modules containers,loaded_libraries` |
| `--config` | YAML config file (see [Config file](#config-file)). Flags given on the command line win. Default: none. | `--config ./config.yaml` |

#### Limits

| Flag | Description | Example |
|---|---|---|
| `--timeout` | Total collection time limit in seconds. Default: `900`. | `--timeout 600` |
| `--module-timeout` | Time limit per module in seconds. Default: `120`. | `--module-timeout 180` |

#### Windows applications

These inputs are read on Windows only. They are usually generated by a tool, not typed.

| Flag | Description | Example |
|---|---|---|
| `--registry-values` | Extra `HKLM` registry values to report in `security_configuration.registry`. A base64url JSON array `[{"key":"SOFTWARE\\...","name":"Value"}]`, or `@<file>` holding the array (plain JSON or base64url). Default: none. | `--registry-values @regvalues.json` |
| `--file-probes` | Files to check for the applications they name; results go to `applications[].file_checks` (exists, file version, signature). A base64url JSON array `[{"id","name","publisher","path","base"}]` where `name`/`publisher` are regular expressions and `base` is `install_location`, `program_files` or `display_icon_dir`; or `@<file>`. Default: none. | `--file-probes @probes.json` |

#### Upload (optional)

Off by default. See [Upload (optional)](#upload-optional).

| Flag | Description | Example |
|---|---|---|
| `--upload` | After writing the file, send it to `--api-url`. Default: `false`. | `--upload` |
| `--api-url` | Ingest URL of an Openness-compatible service. Required with `--upload`. Default: empty. | `--api-url https://ingest.example.org/v1/evidence` |
| `--api-key-env` | Name of the environment variable that holds the API token. Default: `OPENNESS_API_KEY`. | `--api-key-env MY_TOKEN` |
| `--token` | API token on the command line; overrides env and saved credentials. Visible in process lists, prefer the env variable. Default: empty. | `--token "$TOKEN"` |
| `--upload-gzip` | Send the body gzip-compressed (`Content-Encoding: gzip`). Default: `true`. | `--upload-gzip=false` |
| `--allow-insecure-upload` | Allow an `http://` URL. Default: `false` (HTTPS only). | `--allow-insecure-upload` |

#### Debug

| Flag | Description | Example |
|---|---|---|
| `--osquery-path` | Path to `osqueryi`. Optional; native modules do not need it. Default: search `PATH`. | `--osquery-path /opt/osquery/bin/osqueryi` |
| `--force-fail-modules` | Comma-separated modules to mark as failed, to test how consumers handle a partial file. Default: empty. | `--force-fail-modules packages` |
| `--log-level` | Accepted for compatibility; it does not change output yet. Default: `info`. | `--log-level debug` |

### validate

Re-compute the integrity hash and check status values and relationship ids. Prints `OK`,
or one `FAIL:` line per problem and exits `1`. Reads plain and gzip files.

```bash
openness-collector validate ./host.openness
```

| Argument | Description | Example |
|---|---|---|
| `<file>` | The `.openness` (or `.openness.gz`) file to check. Required. | `validate ./host.openness.gz` |

### inspect

Print a short JSON summary: schema version, hostname, platform, privilege, status,
module and inventory counts, integrity hash.

```bash
openness-collector inspect ./host.openness
```

| Argument | Description | Example |
|---|---|---|
| `<file>` | The `.openness` (or `.openness.gz`) file to summarize. Required. | `inspect ./host.openness` |

### upload

Send an existing evidence file. Optional; see [Upload (optional)](#upload-optional).

```bash
OPENNESS_API_KEY=... openness-collector upload --output ./host.openness --api-url https://ingest.example.org/v1/evidence
```

| Flag | Description | Example |
|---|---|---|
| `--output` | Path of the file to send. Required. | `--output ./host.openness` |
| `--api-url` | Ingest URL of an Openness-compatible service. Required. Default: empty. | `--api-url https://ingest.example.org/v1/evidence` |
| `--api-key-env` | Environment variable that holds the API token. Default: `OPENNESS_API_KEY`. | `--api-key-env MY_TOKEN` |
| `--token` | API token on the command line; overrides env and saved credentials. Default: empty. | `--token "$TOKEN"` |
| `--upload-gzip` | Gzip the body (`Content-Encoding: gzip`); a `.gz` file is sent as is. Default: `true`. | `--upload-gzip=false` |
| `--allow-insecure-upload` | Allow an `http://` URL. Default: `false`. | `--allow-insecure-upload` |

### login

Save an API token for uploads. Without `--token` it opens the token page in a browser and
reads the token from standard input. The token is checked against `--check-url` before it
is saved to `~/.config/openness/credentials.json` (directory `0700`, file `0600`; the
`OPENNESS_CONFIG_DIR` environment variable moves it).

```bash
openness-collector login --no-browser
```

| Flag | Description | Example |
|---|---|---|
| `--token` | Token to save, skips the prompt. Visible in process lists. Default: empty. | `--token "$TOKEN"` |
| `--no-browser` | Do not open a browser; print the URL and read the token from stdin. Default: `false`. | `--no-browser` |
| `--token-page` | Page opened to create a token. Default: `https://app.s4e.io/api-token`. | `--token-page https://example.org/token` |
| `--check-url` | URL that validates the token (POST `{"token": ...}`). Default: `https://api.s4e.io/api/auth/check`. | `--check-url https://example.org/auth/check` |

### logout

Delete the saved token file. No flags.

```bash
openness-collector logout
```

### whoami

Check the token that uploads would use (`OPENNESS_API_KEY` or `S4E_API_TOKEN`, then the
saved credentials) against the check URL. Prints `ok source=<where it came from>`.

```bash
openness-collector whoami
```

| Flag | Description | Example |
|---|---|---|
| `--check-url` | URL that validates the token. Default: `https://api.s4e.io/api/auth/check`. | `--check-url https://example.org/auth/check` |

### version

Print `openness-collector <version> schema=<schema version>`. No flags.

### modules

List the modules available on this OS as `<id> <module version> platforms=<os list>`.
No flags. Module details: [docs/MODULES.md](docs/MODULES.md).

### self-test

Run `os_inventory` with short time limits, write a temporary file, validate it and delete
it. Prints `self-test OK platform=<os> ...`. No flags.

---

## Config file

`collect --config <file>` reads a YAML file. Values given as flags win over the file.
Example ([config.example.yaml](config.example.yaml)):

```yaml
config_version: "1.0"

collection:
  timeout_seconds: 900
  module_timeout_seconds: 180
  keep_raw_evidence: true

# Omit modules to run every module for the current OS.
# modules:
#   os_inventory: true
#   packages: true

output:
  path: "./output.openness"
  compression: ""            # "gzip" is the same as --compress

upload:
  enabled: false             # true is the same as --upload
  api_url: ""
  api_key_env: "OPENNESS_API_KEY"
  preserve_local_file: true
  allow_insecure_upload: false
```

```bash
openness-collector collect --config ./config.example.yaml --output ./from-config.openness
```

---

## Upload (optional)

The collector never needs a network connection: the `.openness` file on disk is the result,
and you can move it any way you like. Upload is an optional convenience that sends the file
to an Openness-compatible service given by `--api-url`.

1. The local file is always written first; a failed upload does not remove it.
2. The token comes from `--token`, then the `--api-key-env` variable (default
   `OPENNESS_API_KEY`), then `S4E_API_TOKEN`, then the file saved by `login`.
3. The file is sent with `POST`, `Authorization: Bearer <token>`, and the collection id as
   `Idempotency-Key`.
4. HTTPS is required unless `--allow-insecure-upload` is set.
5. Network errors, HTTP 5xx and 429 are retried up to three times with backoff.

```bash
export OPENNESS_API_KEY='...'
openness-collector collect --output ./host.openness --upload --api-url https://ingest.example.org/v1/evidence
```

---

## Supported platforms

Every pull request runs the full command set on these systems and compares the evidence
with the system's own tools (see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#end-to-end-tests)):

| Platform | How it is tested |
|---|---|
| Ubuntu 24.04 amd64 (GitHub runner) | Native, as root |
| Windows Server 2025 amd64 (GitHub `windows-latest` runner) | Native, as Administrator |
| Ubuntu 20.04, 22.04, 24.04 | Container |
| Debian 12 | Container |
| Rocky Linux 9, AlmaLinux 9 | Container |
| Amazon Linux 2023 | Container |
| openSUSE Leap 15 | Container |
| Alpine 3.20 | Container |
| macOS arm64 | Build and CLI only; no native modules |

Lab hosts used during development: Ubuntu 22.04 aarch64 and Windows Server 2022 amd64.
Known gaps: [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

---

## More documentation

| Document | Contents |
|---|---|
| [docs/EVIDENCE.md](docs/EVIDENCE.md) | `.openness` file format, record shape, status values, integrity and validate |
| [docs/MODULES.md](docs/MODULES.md) | Every Linux and Windows module, step by step |
| [docs/DESIGN.md](docs/DESIGN.md) | Collect pipeline, honesty rules, evidence chains, Python and language inventory, containers, loaded libraries |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build, tests, project layout, versioning, CI and releases |
| [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) | What is not covered |
| [docs/PROMPTS.md](docs/PROMPTS.md) | Context for contributors using AI assistants |

Related tool: [openness-resolver](https://github.com/s4e-io/openness-resolver) (part of
[openness](https://github.com/s4e-io/openness)) reads the `.openness` file and compares the
installed versions with vendor data. That matching logic is intentionally **outside** this
repository.

---

## Openness in S4E

Openness is free to run on your own machines. The same collector and resolver power the
Inside depth of [S4E](https://s4e.io), which adds scheduling, history, multi-host views and
remediation tracking on top. Read more at <https://s4e.io/labs/openness>.

---

## License

Copyright 2026 S4E (Security For Everyone)

Licensed under the [Apache License, Version 2.0](LICENSE). Openness is open source: use it,
modify it and redistribute it, commercially or not, as the license describes. Keep the LICENSE
and NOTICE files with any copy you distribute.

Third-party notices: [NOTICE](NOTICE). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

See also: [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)
