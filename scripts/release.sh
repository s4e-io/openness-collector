#!/usr/bin/env bash
# Local helper: run tests, bump version, create annotated tag, push tag (triggers GitHub Release).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PART="${1:-patch}"
case "$PART" in
  major|minor|patch) ;;
  *)
    echo "Usage: scripts/release.sh [patch|minor|major]" >&2
    exit 1
    ;;
esac

echo "==> go test ./..."
go test ./...

echo "==> bump $PART"
NEW_VERSION="$(bash scripts/version.sh bump "$PART" | tr -d '[:space:]')"
TAG="v${NEW_VERSION}"

echo "==> commit version bump"
git add VERSION internal/version/version.go
git commit -m "chore(release): ${TAG}"

echo "==> tag ${TAG}"
git tag -a "$TAG" -m "Release ${TAG}"

echo "==> push branch + tag"
git push origin HEAD
git push origin "$TAG"

echo "Release workflow will build Linux binaries and publish GitHub Release for ${TAG}."
