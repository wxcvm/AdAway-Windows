#!/usr/bin/env bash
# Independent fixed DNS diagnostic contract; production and rule-core pins stay unchanged.
set -euo pipefail
PIN="6f1f9c69a2513a4ccb18b8da90f0c8527ab6f955"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('dns-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={
 'diagnostic_dns_reply.h':'5136d25014796a8fd34bd72b732c8178b1dd985107333f74aa01895802ed9e93',
 'diagnostic_dns_reply_test.c':'198970cae1b20b25b4936932b1093561627e734d2d18eead7741a8bc5d170a77',
 'diagnostic_dns_vectors.tsv':'b9b964b928d6eda8d075bfe14bb8ccd04aece7d908c6a327144ff4fa2e25688c',
}
actual={}
for p in root.rglob('*'):
    assert not p.is_symlink()
    if p.is_file() and p.name!='manifest.json':
        actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==expected==manifest['files'], 'DNS contract cache changed; preserve before refreshing'
PY
}
if [ ! -e dns-contract ]; then
  stage_root=$(realpath -- "${TMPDIR:-/tmp}")
  stage=$(mktemp -d "$stage_root/adaway-dns.XXXXXX")
  cleanup() {
    resolved=$(realpath -- "$stage")
    case "$resolved" in "$stage_root"/adaway-dns.*) rm -rf -- "$resolved";; *) echo 'Refusing unexpected cleanup target' >&2;; esac
  }
  trap cleanup EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin https://github.com/wxcvm/AdAway.git
  git -C "$stage" fetch --depth 1 origin "$PIN"
  test "$(git -C "$stage" rev-parse 'FETCH_HEAD^{commit}')" = "$PIN"
  mkdir "$stage/contract"
  for name in diagnostic_dns_reply.h diagnostic_dns_reply_test.c diagnostic_dns_vectors.tsv; do
    git -C "$stage" show "FETCH_HEAD:webserver/jni/$name" > "$stage/contract/$name"
    test -s "$stage/contract/$name"
  done
  python3 - "$stage/contract" "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
(root/'manifest.json').write_text(json.dumps({'commit':sys.argv[2], 'files':{
    p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}},sort_keys=True))
PY
  mv "$stage/contract" dns-contract
fi
verify
echo 'Pinned DNS diagnostic contract ready; no production core replacement'
