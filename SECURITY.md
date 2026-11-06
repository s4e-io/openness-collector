# Security Policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report them through one of:

- [GitHub Security Advisories](https://github.com/s4e-io/openness-collector/security/advisories/new) (preferred)
- Email: **support@s4e.io**

We aim to acknowledge reports within **72 hours** and provide a remediation timeline when possible.

## Sensitive data

This project collects host evidence. Never commit:

- Real lab or production passwords
- API keys, tokens, or private keys
- Real `.openness` files from production or customer hosts
- Untracked credential files (use `docs/CREDS.example.md` as a template only)

Upload keys and remote-test credentials must stay in environment variables, never in git.

## Scope

In scope:

- Secret leakage in committed files or default configs
- Credential handling in collect/upload paths
- Cmdline or config redaction bypasses that expose secrets in evidence output

Out of scope:

- Vulnerabilities in third-party tools invoked at collect time (e.g. system package managers) unless openness-collector mishandles their output in an exploitable way
- Issues in the separate [openness-resolver](https://github.com/s4e-io/openness-resolver) project (report there instead)

## Project

Part of the [Openness](https://github.com/s4e-io/openness) project by [S4E IO](https://github.com/s4e-io).
