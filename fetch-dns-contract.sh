#!/usr/bin/env bash
# Independent fixed DNS diagnostic contract; production and rule-core pins stay unchanged.
set -euo pipefail
PIN="fe8034bfec816d18e8d49f279fa77765b3ca21e0"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('dns-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
expected={
 'diagnostic_dns_reply.h':'8d473d5d44fa08a42ab07c4912013711bd01182f7ca173edd76f883fb231d008',
 'diagnostic_dns_reply_test.c':'4b8753a07a71c387fbf9a742fc8ba4715e5a7bbd2a605fbb7dbdfeba75b8c7a1',
 'diagnostic_dns_vectors.tsv':'eee1509e0905b4600f1cdf6b4d865ad340c38441e07588f17df9e75af621ce3a',
 'diagnostic_dns_policy_vectors.tsv':'c5128fc7e3276cb549bf1f3ace4dc673f7e56bc56f8ba9f0ae3189b70ab33f59',
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
  for name in diagnostic_dns_reply.h diagnostic_dns_reply_test.c diagnostic_dns_vectors.tsv diagnostic_dns_policy_vectors.tsv; do
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
