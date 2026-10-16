#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/repo"
cp "$root/fetch-upstream.sh" "$scratch/repo/"
cat > "$scratch/bin/git" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = '-C' ]
directory="$2"; shift 2
case "$1" in
 init|remote) ;;
 fetch)
  [ "$2" = '--depth' ] && [ "$3" = 1 ] && [ "$4" = origin ]
  [ "$5" = 4470606366e614abdb308fdfe94734d28167439c ] ;;
 rev-parse) echo 4470606366e614abdb308fdfe94734d28167439c ;;
 checkout)
  mkdir -p "$directory/webserver/jni/mongoose" "$directory/app/src/main/assets"
  printf 'core\n' > "$directory/webserver/jni/webserver.c"
  printf 'mongoose\n' > "$directory/webserver/jni/mongoose/mongoose.c"
  printf 'test\n' > "$directory/app/src/main/assets/test.html" ;;
 *) exit 99 ;;
esac
MOCK
chmod +x "$scratch/bin/git"
export PATH="$scratch/bin:$PATH"
cd "$scratch/repo"
bash fetch-upstream.sh
bash fetch-upstream.sh
printf 'local edit\n' >> jni/webserver.c
if bash fetch-upstream.sh; then echo 'modified cache was accepted' >&2; exit 1; fi
test "$(tail -1 jni/webserver.c)" = 'local edit'
rm .adblock-upstream-manifest.json
if bash fetch-upstream.sh; then echo 'unproven cache was accepted' >&2; exit 1; fi
test "$(tail -1 jni/webserver.c)" = 'local edit'
echo 'Pinned source fetch: exact SHA, repeatability, tampering and preservation passed'
