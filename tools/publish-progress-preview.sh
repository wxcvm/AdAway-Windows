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
Windows x64 progress preview for inspection. This prerelease adds a current-user installer, an all-users installer, a portable ZIP and a PowerShell installer with pinned SHA-256 verification. Choose one route; details are below.

The current capabilities are transactional bounded subscription import, failure rollback, strict domain-only Hosts/ABP handling and production native snapshot reloads. This is a local listener, not verified whole-machine protection. Full Windows build, transaction/concurrency tests and loopback smoke checks run before publication.

No draft PR is merged. Stable release pointers and update manifests are not changed. MSI, MSIX and public package-manager registration are not yet provided. This preview requires the production Windows Authenticode PFX. The signed webserver and BOTH signed Inno Setup installers are checked against the publisher certificate used for the prior production EXE. Publishing fails rather than shipping an unsigned or different-signer preview. SHA256 checksums also accompany the signatures.

NOTES
cat docs/preview-installation.md docs/m1-rule-loader-validation.md >> preview-notes.md
if [[ "$GITHUB_REF" == refs/tags/* ]]; then
  gh release create "$PREVIEW_TAG" release-assets/* --repo "$GITHUB_REPOSITORY" --verify-tag \
    --prerelease --latest=false --title "ADBlock Windows signed preview $PREVIEW_TAG" \
    --notes-file preview-notes.md
else
  gh release create "$PREVIEW_TAG" release-assets/* --repo "$GITHUB_REPOSITORY" \
    --target "$GITHUB_SHA" --prerelease --latest=false \
    --title "ADBlock Windows signed preview $PREVIEW_TAG" \
    --notes-file preview-notes.md
fi
