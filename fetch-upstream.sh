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
BRANCH="feat/win11-webserver-release"
UPSTREAM="https://github.com/wxcvm/AdAway.git"

need() { [ ! -f jni/webserver.c ] || [ ! -f app/src/main/assets/test.html ]; }

if need; then
  echo "==> fetching upstream core at $PIN"
  rm -rf .upstream
  mkdir -p .upstream
  git -C .upstream init -q
  git -C .upstream remote add origin "$UPSTREAM"
  git -C .upstream fetch --depth 1 origin "$BRANCH"
  got=$(git -C .upstream rev-parse FETCH_HEAD)
  echo "    fetched: $got"
  if [ "$got" != "$PIN" ]; then
    echo "::error::上游提交与 pin 不一致：$got != $PIN（分支前移了？请有意识地重新 pin，并同步契约）"
    exit 1
  fi
  git -C .upstream checkout FETCH_HEAD -- webserver/jni app/src/main/assets
  rm -rf jni app/src/main/assets
  mv .upstream/webserver/jni jni
  mkdir -p app/src/main
  mv .upstream/app/src/main/assets app/src/main/assets
  rm -rf .upstream
else
  echo "==> upstream already present, skip"
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
