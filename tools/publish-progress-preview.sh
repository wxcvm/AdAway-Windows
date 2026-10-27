#!/usr/bin/env bash
set -euo pipefail
case "$GITHUB_REF" in
  refs/tags/progress-win-*)
    PREVIEW_TAG="$GITHUB_REF_NAME";;
  refs/heads/preview/release-*)
    PREVIEW_TAG="progress-win-${GITHUB_REF_NAME#preview/release-}";;
  *)
    echo "::error::not a controlled Windows preview ref"; exit 1;;
esac
if [[ ! "$PREVIEW_TAG" =~ ^progress-win-[0-9]{8}\.[0-9]+$ ]]; then
  echo "::error::malformed preview tag"; exit 1
fi
export PREVIEW_TAG
if gh release view "$PREVIEW_TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  echo "::error::immutable preview tag exists"; exit 1
fi
python3 tools/package-progress-preview.py
if [[ "$GITHUB_REF" == refs/tags/* ]]; then
  gh release create "$PREVIEW_TAG" release-assets/* --repo "$GITHUB_REPOSITORY" --verify-tag \
    --prerelease --latest=false --title "ADBlock Windows in-place preview $PREVIEW_TAG" \
    --notes-file release-assets/PREVIEW-NOTES.md
else
  gh release create "$PREVIEW_TAG" release-assets/* --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" --prerelease --latest=false \
    --title "ADBlock Windows in-place preview $PREVIEW_TAG" \
    --notes-file release-assets/PREVIEW-NOTES.md
fi
python3 tools/publish-preview-channel.py
