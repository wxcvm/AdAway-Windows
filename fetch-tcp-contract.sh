#!/usr/bin/env bash
# Independent fixed transport contract; production core pin stays unchanged.
set -euo pipefail
PIN="51fc8552ad629c5e0aaa76d01225cfb4e29b22f5"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('tcp-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={'diagnostic_socks5.h': '1274c10a58c0f1070ccfffc48264cf9a720ece936b9f2a10c6c80228a1f05222', 'diagnostic_socks5_test.c': '63722c133d2eedea69e81ced9352cef322646ef699eef5f42e5a3f63e6c44122', 'socks5_vectors.tsv': '3da5dc87b5f79f7e0a1acf70b50c0cee72f372123cfbaf186138db1ead644ea8'}
actual={}
for p in root.rglob('*'):
    assert not p.is_symlink()
    if p.is_file() and p.name!='manifest.json': actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==expected==manifest['files'], 'TCP cache changed; preserve before refreshing'
PY
}
if [ ! -e tcp-contract ]; then
  stage_root=$(realpath -- "${TMPDIR:-/tmp}")
  stage=$(mktemp -d "$stage_root/adaway-tcp.XXXXXX")
  cleanup() {
    resolved=$(realpath -- "$stage")
    case "$resolved" in "$stage_root"/adaway-tcp.*) rm -rf -- "$resolved";; *) echo 'Refusing unexpected cleanup target' >&2;; esac
  }
  trap cleanup EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin https://github.com/wxcvm/AdAway.git
  git -C "$stage" fetch --depth 1 origin "$PIN"
  test "$(git -C "$stage" rev-parse 'FETCH_HEAD^{commit}')" = "$PIN"
  mkdir "$stage/contract"
  for name in diagnostic_socks5.h diagnostic_socks5_test.c socks5_vectors.tsv; do
    path="webserver/jni/$name"
    if [ "$name" = socks5_vectors.tsv ]; then path="app/src/test/resources/tcp/$name"; fi
    git -C "$stage" show "FETCH_HEAD:$path" > "$stage/contract/$name"
    test -s "$stage/contract/$name"
  done
  python3 - "$stage/contract" "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
(root/'manifest.json').write_text(json.dumps({'commit':sys.argv[2],'files':{
    p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}},sort_keys=True))
PY
  test "$(dirname -- "$(realpath -m "$PWD/tcp-contract")")" = "$(pwd -P)"
  mv "$stage/contract" tcp-contract
fi
verify
echo 'Pinned authenticated TCP contract verified; no production core replacement'
