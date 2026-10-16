#!/usr/bin/env bash
# Reproducibly compile official OpenSSL 3.5.9 upstream under MSYS2 MINGW64.
# No unverified binary downloads, no process-wide PATH modification.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="openssl-3.5.9"
COMMIT="45e844fa2a14ec92d146bd8f5778ac130b6625fb"
ROOT="$HERE/.openssl-build"
SOURCE="$ROOT/source"
OUT="$ROOT/install"
for cmd in git perl make; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd"; exit 1; }
done
if [[ ! -d "$SOURCE/.git" ]]; then
  mkdir -p "$ROOT"
  git clone --quiet --depth 1 --branch "$TAG" https://github.com/openssl/openssl.git "$SOURCE"
fi
got="$(git -C "$SOURCE" rev-parse HEAD)"
[[ "$got" == "$COMMIT" ]] || {
  echo "ERROR: source commit differs from pinned official release: $got" >&2; exit 1;
}
if [[ -s "$OUT/lib/libssl.a" && -s "$OUT/lib/libcrypto.a" && -f "$OUT/BUILD-COMMIT" ]] &&
   [[ "$(cat "$OUT/BUILD-COMMIT")" == "$COMMIT" ]]; then
  echo "Using previously built OpenSSL 3.5.9"; exit 0
fi

WORK="$ROOT/work"
rm -rf "$WORK"
mkdir -p "$WORK"
git -C "$SOURCE" archive HEAD | tar -xf - -C "$WORK"
pushd "$WORK" >/dev/null
./Configure mingw64 no-shared no-tests no-apps no-docs no-module \
  --prefix="$OUT" --libdir=lib --openssldir="$OUT/ssl"
make -j "${OPENSSL_JOBS:-4}" build_libs
make install_dev
popd >/dev/null
[[ -s "$OUT/lib/libssl.a" && -s "$OUT/lib/libcrypto.a" ]] || {
  echo "Missing OpenSSL archives" >&2; exit 1;
}
echo "$COMMIT" > "$OUT/BUILD-COMMIT"
echo "Official OpenSSL 3.5.9 built for Windows MINGW64"
