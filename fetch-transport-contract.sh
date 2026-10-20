#!/usr/bin/env bash
# Independent fixed transport contract; production core pin stays unchanged.
set -euo pipefail
PIN="7d938c36198f44565407de163721e01c8c55972b"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('transport-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={'diagnostic_udp_packet.h': '0379f574395590b3b0dfad3c9ccf1f5ad1bcc108f527c7ddbd1b0e0e404aac31', 'diagnostic_udp_packet_test.c': '3f74eeecb704fb8e7cea469a6901fba42b02e3461c74ab27696ef9147b6f8d16', 'packet_vectors.tsv': '4325c75790992176109b5bd8509df50ed0933cfcb36842117c8d952f4685cd4e'}
actual={}
for p in root.rglob('*'):
    assert not p.is_symlink()
    if p.is_file() and p.name!='manifest.json': actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==expected==manifest['files'], 'Transport cache changed; preserve before refreshing'
PY
}
if [ ! -e transport-contract ]; then
  stage_root=$(realpath -- "${TMPDIR:-/tmp}")
  stage=$(mktemp -d "$stage_root/adaway-transport.XXXXXX")
  cleanup() {
    resolved=$(realpath -- "$stage")
    case "$resolved" in "$stage_root"/adaway-transport.*) rm -rf -- "$resolved";; *) echo 'Refusing unexpected cleanup target' >&2;; esac
  }
  trap cleanup EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin https://github.com/wxcvm/AdAway.git
  git -C "$stage" fetch --depth 1 origin "$PIN"
  test "$(git -C "$stage" rev-parse 'FETCH_HEAD^{commit}')" = "$PIN"
  mkdir "$stage/contract"
  for name in diagnostic_udp_packet.h diagnostic_udp_packet_test.c packet_vectors.tsv; do
    path="webserver/jni/$name"
    if [ "$name" = packet_vectors.tsv ]; then path="app/src/test/resources/transport/$name"; fi
    git -C "$stage" show "FETCH_HEAD:$path" > "$stage/contract/$name"
    test -s "$stage/contract/$name"
  done
  python3 - "$stage/contract" "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
(root/'manifest.json').write_text(json.dumps({'commit':sys.argv[2],'files':{
    p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}},sort_keys=True))
PY
  test "$(dirname -- "$(realpath -m "$PWD/transport-contract")")" = "$(pwd -P)"
  mv "$stage/contract" transport-contract
fi
verify
echo 'Pinned dual-stack transport contract verified; no production core replacement'
