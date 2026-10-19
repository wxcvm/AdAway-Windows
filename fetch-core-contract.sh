#!/usr/bin/env bash
# Fetch proposed portable M1 contracts independently of the production server.
set -euo pipefail
PIN="5223567cfb192ccd652de9986f262e0f31948d21"
verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('shared-contract')
assert root.is_dir() and not root.is_symlink(), 'invalid contract directory'
manifest=json.loads((root/'manifest.json').read_text())
assert manifest['commit']==sys.argv[1], 'contract pin differs'
actual={}
for p in root.rglob('*'):
    assert not p.is_symlink(), 'symlink in contract cache'
    if p.is_file() and p.name!='manifest.json':
        actual[p.relative_to(root).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==manifest['files'], 'contract cache changed; preserve before refreshing'
PY
}
if [ -e shared-contract ]; then
  verify
else
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin https://github.com/wxcvm/AdAway.git
  git -C "$stage" fetch --depth 1 origin "$PIN"
  test "$(git -C "$stage" rev-parse 'FETCH_HEAD^{commit}')" = "$PIN"
  mkdir "$stage/contract"
  for name in traffic_core_contract.h traffic_core_contract_test.c traffic_core_vectors.txt \
      traffic_core_contract.schema.json rule_norm.h rule_norm_test.c rule_vectors.txt \
      domain_rule_snapshot.h domain_allow_snapshot.h block_rule_snapshot.h subscription_import.h \
      domain_rule_snapshot_test.c block_rule_snapshot_test.c source_loader_vectors.txt \
      typed_rule_record.h typed_rule_snapshot_test.c typed_rule_vectors.tsv; do
    git -C "$stage" show "FETCH_HEAD:webserver/jni/$name" > "$stage/contract/$name"
    test -s "$stage/contract/$name"
  done
  python3 - "$stage/contract" "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
(root/'manifest.json').write_text(json.dumps({'commit':sys.argv[2],'files':files},sort_keys=True))
PY
  mv "$stage/contract" shared-contract
  verify
fi
echo 'Shared M1 contract SHA and cache verified; production core pin unchanged'
