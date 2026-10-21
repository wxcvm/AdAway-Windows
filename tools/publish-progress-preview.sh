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
cat > preview-notes.md <<'NOTES'
Windows x64 in-place preview. The installer uses the production AppId and upgrades the existing installation, preserving settings and resources. No separate Preview app is installed. A portable ZIP and SHA-256-pinned PowerShell installer are attached.

Reviewed changes are merged after CI passes. Stable release pointers and update manifests are unchanged by this preview. The repository currently permits unsigned Windows distributions: SHA-256 checksums verify download integrity, not an Authenticode publisher identity. MSI, MSIX and package-manager registration are not provided.

NOTES
cat docs/preview-installation.md docs/listener-settings.md docs/listener-lifecycle.md >> preview-notes.md
cat docs/preview-updates.md >> preview-notes.md
cat docs/dual-stack-transport.md >> preview-notes.md
cat docs/query-log-paging.md >> preview-notes.md
if [[ "$GITHUB_REF" == refs/tags/* ]]; then
  gh release create "$PREVIEW_TAG" release-assets/* --repo "$GITHUB_REPOSITORY" --verify-tag \
    --prerelease --latest=false --title "ADBlock Windows in-place preview $PREVIEW_TAG" \
    --notes-file preview-notes.md
else
  gh release create "$PREVIEW_TAG" release-assets/* --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" --prerelease --latest=false \
    --title "ADBlock Windows in-place preview $PREVIEW_TAG" \
    --notes-file preview-notes.md
fi
python3 tools/publish-preview-channel.py
