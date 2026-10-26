#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
JNI="${ADBLOCK_JNI:-$HERE/jni}"
source "$HERE/scripts/gui-sources.sh"
SSL_PREFIX="$HERE/.openssl-build/install"
mkdir -p .gui-test
cp dist/*.dll .gui-test/ 2>/dev/null || true
# Same GUI sources, pinned OpenSSL and dependencies; no production core main().
gcc -std=c11 -O2 -Wall -mwindows -D MG_ENABLE_IPV6 -DMG_TLS=MG_TLS_OPENSSL -DMG_ENABLE_POLL=1 \
  -I. -I"$JNI" -Ishared-contract -Itransport-contract -Itcp-contract -Ilog-contract \
  -I"$SSL_PREFIX/include" -I"$MINGW_PREFIX/include" \
  tools/query-log-gui-driver.c "${GUI_SOURCES[@]}" "$JNI/mongoose/mongoose.c" app_res.o \
  "$SSL_PREFIX/lib/libssl.a" "$SSL_PREFIX/lib/libcrypto.a" \
  -lws2_32 -lwinmm -lpthread -lgdi32 -luser32 -lcomdlg32 -lshell32 -ladvapi32 \
  -lcrypt32 -liphlpapi -ldwmapi -luxtheme -lpsapi -lwinhttp -lbcrypt -lwintrust \
  -o .gui-test/query-log-gui-driver.exe
