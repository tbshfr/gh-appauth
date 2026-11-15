#!/usr/bin/env bash
# Usage: scripts/release.sh [VERSION]
#   VERSION defaults to `git describe --tags --always --dirty` (or "dev").
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
DIST=dist
LDFLAGS="-s -w -X main.version=${VERSION}"

rm -rf "${DIST}"
mkdir -p "${DIST}"

build() {
    local goos="$1" goarch="$2" pkg="$3" name="$4"
    echo "building ${name}"
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
        go build -trimpath -ldflags="${LDFLAGS}" -o "${DIST}/${name}" "${pkg}"
}

# `gh extension install` picks the first asset whose name ends in
# "<os>-<arch>[.exe]", so only the extension may use that suffix; the broker
# uses underscores.
build linux amd64 . linux-amd64
build linux arm64 . linux-arm64
build darwin amd64 . darwin-amd64
build darwin arm64 . darwin-arm64
build windows amd64 . windows-amd64.exe
build windows arm64 . windows-arm64.exe

build linux amd64 ./cmd/gh-appauth-broker "gh-appauth-broker_${VERSION}_linux_amd64"
build linux arm64 ./cmd/gh-appauth-broker "gh-appauth-broker_${VERSION}_linux_arm64"

(cd "${DIST}" && sha256sum -- * > checksums.txt)
echo
cat "${DIST}/checksums.txt"
echo
echo "version: ${VERSION}"
echo "artifacts in ${DIST}/"
