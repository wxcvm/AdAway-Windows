#!/usr/bin/env bash
# Independent fixed transport contract; production core pin stays unchanged.
set -euo pipefail
PIN="14126e9c4417a26ab29f41565e952c56ef3b4c30"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('log-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={'query_log_store.inc': '85ca2dd6b8e3d2a03c0b1a7a465db7b72b976b88e0d8a5d08ddb7c59c52c32fb', 'query_log_store_test.c': 'a04d498fc2e24ffb28ab8871bdce9b19c0ed914a5109a8927f287b4e153ea8ca', 'request_host.h': '5966a9627eeb4e8a96f244e2ac4665f119ec6bcb1d8f38e1831a6606048f1272', 'request_host_test.c': 'f15e2cb75d5f755dab6eec214c688d42866f715d381aa003a0916eedab7ee7d4', 'stats-json-bounds-fixture.py': '5e691c51417efe1b1413f0d7cab30646662484031d8da95a6d00e76f3db11a2a'}
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
