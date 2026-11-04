#!/usr/bin/env bash
# Read or bump the project version in VERSION (semver X.Y.Z).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION_FILE="$ROOT/VERSION"

usage() {
  cat <<'EOF'
Usage:
  scripts/version.sh              # print current version
  scripts/version.sh get          # print current version
  scripts/version.sh tag          # print v-prefixed tag (vX.Y.Z)
  scripts/version.sh bump patch   # 0.4.7 -> 0.4.8
  scripts/version.sh bump minor   # 0.4.7 -> 0.5.0
  scripts/version.sh bump major   # 0.4.7 -> 1.0.0
  scripts/version.sh set X.Y.Z    # set exact version
EOF
}

current() {
  tr -d '[:space:]' <"$VERSION_FILE"
}

write_version() {
  local v="$1"
  if [[ ! "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "invalid semver: $v" >&2
    exit 1
  fi
  printf '%s\n' "$v" >"$VERSION_FILE"
  # Keep Go default in sync for local `go run` without ldflags.
  perl -i -pe "s/Version = \"[^\"]+\"/Version = \"$v\"/" "$ROOT/internal/version/version.go"
  echo "$v"
}

bump() {
  local part="$1"
  local cur
  cur="$(current)"
  local major minor patch
  IFS=. read -r major minor patch <<<"$cur"
  case "$part" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) echo "unknown bump part: $part (use major|minor|patch)" >&2; exit 1 ;;
  esac
  write_version "${major}.${minor}.${patch}"
}

cmd="${1:-get}"
case "$cmd" in
  get|"") current; echo ;;
  tag) echo "v$(current)" ;;
  set)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    write_version "$2"
    ;;
  bump)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    bump "$2"
    ;;
  -h|--help|help) usage ;;
  *) usage; exit 1 ;;
esac
