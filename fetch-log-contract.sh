#!/usr/bin/env bash
# Independent fixed transport contract; production core pin stays unchanged.
set -euo pipefail
PIN="e7eb7b8ed392104287e6dfdd0e1ab20f1e236163"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('log-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={'query_log_store.inc': 'fcc607c02f991ac6c94c065fdcaf319b9429db3af00a0aa2ac1b6ded83ef3cc8', 'query_log_store_test.c': 'a717fd69eb3f2af84827310178f1fc86a6e9f6c0d2019ebbad0f7c2078ff4ae7', 'request_host.h': '5966a9627eeb4e8a96f244e2ac4665f119ec6bcb1d8f38e1831a6606048f1272', 'request_host_test.c': 'f15e2cb75d5f755dab6eec214c688d42866f715d381aa003a0916eedab7ee7d4', 'stats-json-bounds-fixture.py': '5e691c51417efe1b1413f0d7cab30646662484031d8da95a6d00e76f3db11a2a'}
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
  for name in query_log_store.inc query_log_store_test.c request_host.h request_host_test.c; do
    path="webserver/jni/$name"
    git -C "$stage" show "FETCH_HEAD:$path" > "$stage/contract/$name"
    test -s "$stage/contract/$name"
  done
  git -C "$stage" show "FETCH_HEAD:tools/stats-json-bounds-fixture.py" > "$stage/contract/stats-json-bounds-fixture.py"
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
