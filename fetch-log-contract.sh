#!/usr/bin/env bash
# Independent fixed transport contract; production core pin stays unchanged.
set -euo pipefail
PIN="7bf7e655390bde2608180a191bcec9934d1235bd"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('log-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={'query_log_store.inc': 'fcc607c02f991ac6c94c065fdcaf319b9429db3af00a0aa2ac1b6ded83ef3cc8', 'query_log_store_test.c': 'db3e5964c83c8c74a83aaa76ecc6827397529b04d36bbfe29066b029529cf9fd', 'request_host.h': 'ab0f8070b244d09a5ef7c04df711e2b40c0cf388826985c045f3f115099417b4', 'request_host_test.c': '6d73d1dbc5a850c2807bb79a6cfa42774d054e8d7ea14359e4fea60bc6d14e69', 'stats-json-bounds-fixture.py': '5e691c51417efe1b1413f0d7cab30646662484031d8da95a6d00e76f3db11a2a'}
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
