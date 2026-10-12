#!/usr/bin/env bash
# 取出上游（AdAway 仓库）的 C 服务端核心与 webroot 资源。
#
# 为什么是"取出"而不是"复制进本仓库"：把同一份 C 代码复制两份，两边会各自漂移 —— 历史上正是这样
# 分叉的。这里按**固定提交**取一次（并断言取到的就是被 pin 的那一个），分支前移会大声失败，
# 迫使重新 pin；改 pin 时请同步更新 docs/windows-core-contract.md（在 AdAway 仓库里）。
#
# 幂等：目标已存在就直接跳过，因此可以在多个步骤里安全调用。
set -euo pipefail

PIN="4470606366e614abdb308fdfe94734d28167439c"
UPSTREAM="https://github.com/wxcvm/AdAway.git"

verify() {
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path('.')
manifest=json.loads((root/'.adblock-upstream-manifest.json').read_text())
assert manifest['commit']==sys.argv[1], 'cached source pin differs'
actual={}
for folder in ['jni','app/src/main/assets']:
    assert (root/folder).is_dir() and not (root/folder).is_symlink(), 'invalid source-cache directory'
    for p in sorted((root/folder).rglob('*')):
        assert not p.is_symlink(), 'symlink in source cache'
        if p.is_file(): actual[p.as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==manifest['files'], 'cached source was changed; preserve local edits before refreshing'
PY
}

if [ -e jni ] || [ -e app/src/main/assets ]; then
  if [ ! -f .adblock-upstream-manifest.json ]; then
    echo 'ERROR: existing source cache has no verified provenance; preserve it before refreshing' >&2
    exit 1
  fi
  verify
  echo '==> cached source and pinned manifest verified'
else
  echo "==> fetching upstream core at $PIN"
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
  git -C "$stage" init -q
  git -C "$stage" remote add origin "$UPSTREAM"
  git -C "$stage" fetch --depth 1 origin "$PIN"
  got=$(git -C "$stage" rev-parse 'FETCH_HEAD^{commit}')
  echo "    fetched: $got"
  if [ "$got" != "$PIN" ]; then
    echo "::error::上游提交与 pin 不一致：$got != $PIN（分支前移了？请有意识地重新 pin，并同步契约）"
    exit 1
  fi
  git -C "$stage" checkout FETCH_HEAD -- webserver/jni app/src/main/assets
  mv "$stage/webserver/jni" jni
  mkdir -p app/src/main
  mv "$stage/app/src/main/assets" app/src/main/assets
  python3 - "$PIN" <<'PY'
import hashlib,json,pathlib,sys
files={}
for folder in ['jni','app/src/main/assets']:
    for p in sorted(pathlib.Path(folder).rglob('*')):
        assert not p.is_symlink(), 'symlink in source cache'
        if p.is_file(): files[p.as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
pathlib.Path('.adblock-upstream-manifest.json').write_text(json.dumps({'commit':sys.argv[1],'files':files},sort_keys=True))
PY
  verify
fi

# 取完必须自证：缺失就明确报错，而不是让后面的步骤莫名其妙地失败
for f in jni/webserver.c jni/mongoose/mongoose.c app/src/main/assets/test.html; do
  if [ ! -f "$f" ]; then
    echo "::error::上游文件缺失：$f"
    ls -la jni 2>/dev/null || true
    exit 1
  fi
done
echo "    webserver.c=$(wc -c < jni/webserver.c) bytes, test.html=$(wc -c < app/src/main/assets/test.html) bytes"
