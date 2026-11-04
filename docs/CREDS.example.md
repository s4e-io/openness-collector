# Lab credentials example

Copy this file to `CREDS.md` (gitignored) or export env vars.

Do not commit real passwords.

## Linux (SSH)

```bash
export LINUX_HOST=192.0.2.10
export LINUX_USER=collector
export LINUX_PASS='change-me'
```

## Windows (WinRM)

```bash
export WIN_HOST=192.0.2.20
export WIN_USER=Administrator
export WIN_PASS='change-me'
```

## Notes

- Lab helper scripts require these env vars.
- The collector binary itself never uses these values.
- Prefer SSH keys over passwords when you can.
