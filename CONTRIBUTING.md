# Contributing to openness-collector

Thank you for your interest in contributing.

**Project home:** [github.com/s4e-io/openness](https://github.com/s4e-io/openness)  
**This repository:** [github.com/s4e-io/openness-collector](https://github.com/s4e-io/openness-collector)

## How we build this project

We are transparent about tooling:

- **Development:** maintainers and contributors use AI coding assistants (e.g. Cursor, Claude, Copilot) to draft, refactor, and review code.
- **Runtime:** this collector does **not** use AI. It reads local system state and writes deterministic `.openness` evidence files.

If you use AI while contributing, you remain responsible for the change: read the diff, run tests, and ensure no secrets or host-specific data are committed.

**Using Cursor / Claude / Copilot?** Paste context from [docs/PROMPTS.md](docs/PROMPTS.md) — project purpose, pipeline, schema/modules, and copy-paste prompts.

## Before you start

1. Read [README.md](README.md) and [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).
2. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
3. For security expectations, see [SECURITY.md](SECURITY.md).
4. Third-party licenses shipped with this binary are listed in [NOTICE](NOTICE).

## Development setup

Requirements: Go 1.26+ (see `go.mod`), Linux/macOS/Windows for local builds.

```bash
go test ./...
go run ./cmd/openness-collector version
go run ./cmd/openness-collector self-test
bash scripts/build.sh   # optional: cross-platform binaries in dist/
```

## Pull requests

1. Fork and branch from `dev` (the default branch). Pull requests go to `dev`; `main` holds released versions.
2. Keep changes focused; one logical change per PR.
3. Run `gofmt`, `go vet ./...`, and `go test ./...` before opening the PR (CI enforces these).
4. Update README or `docs/` if behavior, CLI flags, or schema changes.
5. Do **not** commit real credentials, production `.openness` files, or lab secrets.

## Coding guidelines

- Match existing package layout and naming in `internal/`.
- Add or update tests for bug fixes and new behavior.
- Linux module changes: add tests under `internal/modules/linux/`.
- Windows module changes: extend `internal/modules/windows/` tests where possible.
- Preserve secret redaction in cmdline and config paths.
- Schema changes require bumping `SchemaVersion` in `internal/schema/document.go` and documenting in README.

## Versioning

- Release version lives in `VERSION` and `internal/version/version.go` (must stay in sync).
- Use `scripts/version.sh` and `scripts/release.sh` for maintainers cutting releases.
- Record user-visible changes in [CHANGELOG.md](CHANGELOG.md).

## Bug reports

Open a [GitHub issue](https://github.com/s4e-io/openness-collector/issues) with:

- OS and architecture (e.g. Ubuntu 22.04 amd64, Windows Server 2022)
- Collector version (`openness-collector version`)
- Steps to reproduce
- Expected vs actual behavior
- Redacted sample output if relevant (no production host data)

For security issues, see [SECURITY.md](SECURITY.md).

## License

This project is open source under the [Apache License, Version 2.0](LICENSE).

By contributing, you agree that:

1. your contribution is licensed under the [Apache License, Version 2.0](LICENSE), as described in
   Section 5 of the license (inbound = outbound);
2. you have the right to submit your contribution under these terms.

Contributions of every kind are welcome: bug reports, test environments, validation of
findings, new platforms and feeds.
