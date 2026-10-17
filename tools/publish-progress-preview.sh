#!/usr/bin/env bash
set -euo pipefail
python3 tools/package-progress-preview.py
cat > preview-notes.md <<'NOTES'
Windows x64 progress preview for inspection. This prerelease adds a current-user installer, an all-users installer, a portable ZIP and a PowerShell installer with pinned SHA-256 verification. Choose one route; details are below.

The current capabilities are transactional bounded subscription import, failure rollback, strict domain-only Hosts/ABP handling and production native snapshot reloads. This is a local listener, not verified whole-machine protection. Full Windows build, transaction/concurrency tests and loopback smoke checks run before publication.

No draft PR is merged. Stable release pointers and update manifests are not changed. MSI, MSIX and public package-manager registration are not yet provided. Packages may be unsigned; checksums do not establish publisher trust.

NOTES
cat docs/preview-installation.md docs/m1-rule-loader-validation.md >> preview-notes.md
gh release create "$GITHUB_REF_NAME" release-assets/* --repo "$GITHUB_REPOSITORY" --verify-tag \
  --prerelease --latest=false --title "ADBlock Windows progress preview $GITHUB_REF_NAME" --notes-file preview-notes.md
