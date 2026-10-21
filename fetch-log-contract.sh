#!/usr/bin/env bash
# Independent fixed transport contract; production core pin stays unchanged.
set -euo pipefail
PIN="6a43cfdc88f5946e112bfd89c649406b345aa0a3"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('log-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={'query_log_store.inc': '48290bd502594b5d82f1a92807dae6ba67cb3c5837a715ae34f1599c69342461', 'query_log_store_test.c': 'a98a80acee4ca721016d29b41f6b8448c09538f65d8c1acf2e394ac6e6b1e1a8'}
actual={}
for p in root.rglob('*'):
    assert not p.is_symlink()
    if p.is_file() and p.name!='manifest.json': actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==expected==manifest['files'], 'Log contract cache changed; preserve before refreshing'
PY
}
if [ ! -e log-contract ]; then
  stage_root=$(realpath -- "${TMPDIR:-/tmp}")
  stage=$(mktemp -d "$stage_root/adaway-log.XXXXXX")
  cleanup() {
    resolved=$(realpath -- "$stage")
    case "$resolved" in "$stage_root"/adaway-log.*) rm -rf -- "$resolved";; *) echo 'Refusing unexpected cleanup target' >&2;; esac
  }
  trap cleanup EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin https://github.com/wxcvm/AdAway.git
  git -C "$stage" fetch --depth 1 origin "$PIN"
  test "$(git -C "$stage" rev-parse 'FETCH_HEAD^{commit}')" = "$PIN"
  mkdir "$stage/contract"
  for name in query_log_store.inc query_log_store_test.c; do
    path="webserver/jni/$name"
    git -C "$stage" show "FETCH_HEAD:$path" > "$stage/contract/$name"
    test -s "$stage/contract/$name"
  done
  python3 - "$stage/contract" "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
(root/'manifest.json').write_text(json.dumps({'commit':sys.argv[2],'files':{
    p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}},sort_keys=True))
PY
  test "$(dirname -- "$(realpath -m "$PWD/log-contract")")" = "$(pwd -P)"
  mv "$stage/contract" log-contract
fi
verify
echo 'Pinned query log contract verified; no production core replacement'
