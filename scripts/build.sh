#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' <VERSION)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_ID="${BUILD_ID:-${VERSION}-${COMMIT}}"
LDFLAGS="-s -w -X github.com/s4e-io/openness-collector/internal/version.Version=${VERSION} -X github.com/s4e-io/openness-collector/internal/version.Commit=${COMMIT} -X github.com/s4e-io/openness-collector/internal/version.Date=${DATE}"

mkdir -p dist

echo "building version=${VERSION} commit=${COMMIT}"

echo "building linux/arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-collector_${VERSION}_linux_arm64" ./cmd/openness-collector

echo "building linux/amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-collector_${VERSION}_linux_amd64" ./cmd/openness-collector

echo "building windows/amd64..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-collector_${VERSION}_windows_amd64.exe" ./cmd/openness-collector

echo "building darwin/arm64 (local)..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-collector_${VERSION}_darwin_arm64" ./cmd/openness-collector

ls -lh dist/
