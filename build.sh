#!/bin/sh
# Build static binaries and container images (.tar) for every MikroTik arch.
# Requirements: Go 1.24+, Python 3. No Docker needed.
#   ./build.sh            -> dist/
#   VERSION=1.0.0 ./build.sh
set -eu

VERSION="${VERSION:-0.1.0}"
LDFLAGS="-s -w -X github.com/takobas/vartadns/internal/app.Version=${VERSION}"
CA="${CA_BUNDLE:-dist/ca-certificates.crt}"
mkdir -p dist

# CA bundle for HTTPS (DoH upstreams, list downloads). Built from the
# Mozilla set shipped by the ca-certificates package, not from locally
# added CAs.
if [ ! -s "$CA" ]; then
    cat /usr/share/ca-certificates/mozilla/*.crt > "$CA"
fi

build() { # goarch goarm docker-arch docker-variant
    out="dist/vartadns-linux-$1${2:+v$2}"
    echo "== $out"
    CGO_ENABLED=0 GOOS=linux GOARCH="$1" GOARM="$2" \
        go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/vartadns
    python3 tools/mkimage.py --binary "$out" --arch "$3" ${4:+--variant "$4"} \
        --ca "$CA" --config deploy/config.json \
        --tag "vartadns:${VERSION}" --out "dist/vartadns-${VERSION}-$3${4}.tar"
}

build amd64 ""  amd64 ""     # CHR, x86, Proxmox
build arm64 ""  arm64 ""     # CCR2004/2116/2216, RB5009, hAP ax2/ax3, L009
build arm   7   arm   v7     # hAP ac2/ac3, RB4011, RB3011 and other 32-bit ARM

( cd dist && sha256sum vartadns-* > SHA256SUMS )
ls -la dist
