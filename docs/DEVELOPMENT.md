# Development

Build, test and release notes for contributors. See also [CONTRIBUTING.md](../CONTRIBUTING.md).

[Back to README](../README.md)

## Build steps

Script: `scripts/build.sh`

1. Read `VERSION` and the git commit; inject them with `-ldflags` into `internal/version`.
2. Create `dist/`.
3. Build with `CGO_ENABLED=0` and `-trimpath`.
4. Emit these binaries (same names as the release assets):
   - `dist/openness-collector_<version>_linux_arm64`
   - `dist/openness-collector_<version>_linux_amd64`
   - `dist/openness-collector_<version>_windows_amd64.exe`
   - `dist/openness-collector_<version>_darwin_arm64`
5. Print file sizes.

Example one-target build:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/openness-collector_dev_linux_amd64 ./cmd/openness-collector
```

## Lab helper scripts

These scripts are for developers.  
They are **not** part of the collector runtime.

Note: only `scripts/build.sh`, `scripts/release.sh` and `scripts/version.sh` are in this
repository today. The remote lab scripts below are listed for reference and are not shipped.

| Script | Purpose |
|---|---|
| `scripts/build.sh` | Cross-compile binaries |
| `scripts/run_remote_test.sh` | One remote Linux+Windows collect |
| `scripts/continuous_tick.sh` | Repeatable lab tick |
| `scripts/assert_tick.sh` | Assert tick outputs |
| `scripts/prove_partial.sh` | Prove partial status handling |

### Required env vars for remote scripts

```bash
export LINUX_HOST=...
export LINUX_USER=...
export LINUX_PASS=...
export WIN_HOST=...
export WIN_USER=...
export WIN_PASS=...
```

See `docs/CREDS.example.md`.  
Do not commit real passwords.

## Project layout

```text
cmd/openness-collector/     # main entry
tools/hostcheck/            # end-to-end checker used by CI
internal/cli/               # cobra commands
internal/collect/           # engine + module registry
internal/schema/            # document schema + versions
internal/evidencefile/           # write / load / validate / hash
internal/config/            # YAML config
internal/upload/            # optional HTTP upload
internal/osquery/           # optional osquery helper
internal/modules/common/    # shared module helpers
internal/modules/linux/     # Linux native modules
internal/modules/windows/   # Windows native modules
internal/modules/osquerymod/# osquery fallback packs
scripts/                    # build + lab helpers
docs/                       # limitations and notes
config.example.yaml         # sample config
```

## Security notes for contributors

1. This repo must not contain real lab passwords.
2. Use `docs/CREDS.example.md` as a template only.
3. Never commit real credentials (use a local untracked file).
4. Remote scripts fail if credential env vars are missing.
5. Do not commit real `.openness` files from production hosts.
6. Cmdline redaction reduces secrets in evidence, but it is not perfect.
7. Prefer running with least privilege only when you accept missing evidence.
8. Upload keys must stay in environment variables, never in git.

## Development checks

```bash
# unit + integration tests
go test ./...

# local CLI smoke (works on macOS/Linux/Windows build host)
go run ./cmd/openness-collector version
go run ./cmd/openness-collector modules
go run ./cmd/openness-collector self-test
```

## End-to-end tests

`tools/hostcheck` runs the built binary on a real host and checks the evidence against the
host's own tools. CI (`e2e-*` jobs in `.github/workflows/ci.yml`) runs it on `ubuntu-latest`
(as root), on `windows-latest`, and inside containers of Ubuntu 20.04/22.04/24.04, Debian 12,
Rocky 9, Alma 9, Amazon Linux 2023, openSUSE Leap 15 and Alpine 3.20.

What it checks:

- every command and every flag runs: `collect` (full run plus `--modules`,
  `--exclude-modules`, `--force-fail-modules`, `--compress`, `--keep-raw-evidence=false`,
  `--config`, `--build-id`, `--upload` and bad `--registry-values` / `--file-probes` input),
  `validate` (good, tampered, missing and gzip files), `inspect`, `upload`, `login`,
  `whoami`, `logout`, `version`, `modules`, `self-test` and `--help` of each; a command in
  `--help` that the checker does not know fails the run;
- upload and login go to a local HTTP stub, so nothing leaves the machine: the stub checks
  the body, gzip, the bearer token and the `Idempotency-Key`;
- the evidence passes `validate`, every module for the OS ran with a valid status, and
  `collection.status` agrees with the module statuses;
- Linux: `operating_system` equals `/etc/os-release` (`ID`, `VERSION_ID`,
  `VERSION_CODENAME`, `PRETTY_NAME`) and `uname` (kernel, hostname, machine); the package
  list equals `dpkg-query -W`, `rpm -qa` or `apk list --installed` by name, architecture
  and exact version; `/etc/machine-id`;
- Windows: caption, version and build equal `Get-CimInstance Win32_OperatingSystem`; the
  patch ids equal `Get-HotFix`; every machine uninstall-registry entry is in `applications`
  with its version, and Git's version agrees with `git --version`; `--registry-values` and
  `--file-probes` return the registry value and the Git file check;
- both: a TCP listener the checker opens on port 47123 is in `listening_ports` with the
  checker's PID, and the given user is in `users`.

Run it locally:

```bash
go build -o openness-collector ./cmd/openness-collector
go build -o hostcheck ./tools/hostcheck
sudo ./hostcheck -bin ./openness-collector -user "$USER"

# a distro in Docker (static binaries, linux/<your arch>)
GOOS=linux CGO_ENABLED=0 go build -o bin/openness-collector ./cmd/openness-collector
GOOS=linux CGO_ENABLED=0 go build -o bin/hostcheck ./tools/hostcheck
docker run --rm -v "$PWD/bin:/w:ro" rockylinux/rockylinux:9 /w/hostcheck -bin /w/openness-collector -user root
```

`internal/cli/readme_test.go` fails when a command or flag defined in code is missing from
the Usage section of README.md.

## Version source of truth

Do not trust old docs over code.

- Release version: `VERSION` (semver `X.Y.Z`)
- Injected into binaries via `internal/version` ldflags
- Schema version: `internal/schema/document.go` → `SchemaVersion`

Current values: see `VERSION` and `SchemaVersion` (schema **1.6.0**).

### CI and releases

GitHub Actions:

1. **CI** (`.github/workflows/ci.yml`) on push/PR → gofmt, `go vet`, version/schema consistency, govulncheck, `go test ./...` on Linux, Windows and macOS, a smoke collect per OS, the end-to-end `hostcheck` jobs above, and a cross-compiled build of the four release binaries
2. **Nightly** (`.github/workflows/nightly.yml`) every night at 02:00 UTC and by hand → `hostcheck` on more runner images (Ubuntu 22.04 and 24.04, Windows Server 2022 and 2025) and more distros (Ubuntu 20.04 to 24.04, Debian 11 to 13, Rocky and Alma 8 and 9, Amazon Linux 2 and 2023, openSUSE Leap 15, Alpine 3.20 to 3.22) with images pulled fresh that night, and a smoke run of the latest published release binary after its SHA256SUMS check. A failed scheduled run opens one issue labelled `nightly` (later failures comment on it); the next green run closes it.
3. **Release** (`.github/workflows/release.yml`) on tag `vX.Y.Z` → tests, builds four binaries, keyless-signs `SHA256SUMS`, verifies the signature in CI, publishes:
   - `openness-collector_X.Y.Z_linux_amd64` / `_linux_arm64`
   - `openness-collector_X.Y.Z_windows_amd64.exe` (no Authenticode)
   - `openness-collector_X.Y.Z_darwin_arm64` (not notarized; no darwin/amd64 or windows/arm64 yet)
   - `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem`

Cosign CLI is pinned (`cosign-release: v2.4.3` via `sigstore/cosign-installer@v4.1.2`). Detached signature+cert are used (portable); do not assume cosign v3 `--bundle` unless the pin is raised.

#### Verify a release checksum file

```bash
# after downloading SHA256SUMS, SHA256SUMS.sig, SHA256SUMS.pem from the GitHub Release
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp 'https://github.com/s4e-io/openness-collector/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum -c SHA256SUMS
```

Tag must match `VERSION`. Helper:

```bash
# runs tests, bumps VERSION, commits, tags, pushes (triggers release)
bash scripts/release.sh patch   # or: minor | major
```

Manual bump only:

```bash
bash scripts/version.sh bump patch
# commit VERSION + internal/version/version.go, then:
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin HEAD && git push origin vX.Y.Z
```
