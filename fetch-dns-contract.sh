#!/usr/bin/env bash
# Independent fixed DNS diagnostic contract; production and rule-core pins stay unchanged.
set -euo pipefail
PIN="6f1f9c69a2513a4ccb18b8da90f0c8527ab6f955"
if [ -e dns-contract ]; then
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('dns-contract')
assert root.is_dir() and not root.is_symlink()
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1]
actual={}
for p in root.rglob('*'):
    assert not p.is_symlink()
    if p.is_file() and p.name!='manifest.json':
        actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==manifest['files'], 'DNS contract cache changed; preserve before refreshing'
PY
else
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
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
echo 'Pinned DNS diagnostic contract ready; no production core replacement'
