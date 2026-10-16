# M0: storage and acquisition hardening

Depends on draft PR #1 (`feat/traffic-mode-foundation`). No merge or release is authorized by this phase.

## Changes and capabilities

- Reject default routes for every capture input. Even a caller setting every readiness flag cannot activate scoped capture: no production recovery executor exists.
- Seal journal **model** data with per-user DPAPI and a random sealed HMAC-SHA256 key authenticating the entire DPAPI blob, explicit current-user/SYSTEM file permissions, random exclusive temporary files, flush-before-replace, and an exclusive per-operation lock. Reject plaintext v1, corrupt/truncated ciphertext, reparse files and foreign-owned files.
- Fetch the exact upstream Git object `4470606366e614abdb308fdfe94734d28167439c`, verify the object ID, and record/check all cached source hashes. Preserve unproven or locally edited caches by refusing replacement.
- Optional Wintun discovery reads bounded PE export metadata directly from the application directory, without entering the DLL loader, resolving forwarded exports or calling any function. It reports unverified API presence, never a verified/running driver. Direct and forwarded fake-DLL regression traps verify no entry point executes; malformed PE data is rejected. M3 must verify the official artifact, publisher and license before normal DLL loading or adapter creation.

## Checks

Local Linux: the four existing portable C suites pass with `-std=c11 -O2 -Wall -Wextra -Werror -pedantic`; capture testing also covers all 128 readiness-flag combinations. `bash tests/fetch-upstream-test.sh` verifies exact-SHA acquisition, repeatability, cache modification rejection, and local-edit preservation without network access.

Windows CI must execute `windows_network_journal_store_win32_test.exe` linked with `crypt32`, `advapi32`, and `bcrypt`, plus the existing application/installer smoke workflow. Current results and exact run links are maintained in the PR description. Passing mock acquisition is not proof of GitHub access; the actual workflow also fetches and builds the pinned upstream object.

## External acceptance: BLOCKED

This Linux workspace has no real Windows host. DPAPI/ACL/lock behavior must be confirmed on Windows CI. Actual OS route/DNS rollback, crash recovery of real OS changes, user switching, sleep/resume, IPv6 and physical-machine E2E are **not implemented or verified**.

The encrypted store is not a recovery engine: it has no old/new OS values, OS ownership conflict checks, durable transaction execution or startup replay. Its lock serializes individual storage operations, not the entire lifetime of a future network transaction. A storage path must be placed under a managed private directory by that future backend. Same-user replay of an old valid encrypted model is not prevented. No file contents can authorize a network mutation.

Legacy model migration: keep the old file for inspection and create a fresh v2 model at a new path; never automatically execute or reinterpret a legacy model. Failed writes leave the last committed file intact; orphan temporary files are never used for recovery.

## Device/VM verification procedure

1. Run the native store suite under two independent process instances; confirm lock contention cannot overwrite the active snapshot.
2. Inspect the DACL and owner of the journal, lock and temporary files: only the current user/SYSTEM may access newly created files.
3. Kill the test writer before replacement and corrupt/truncate the resulting file. Loading must fail without altering a sentinel in-memory state.
4. Verify no routes, DNS configuration, interfaces or default listeners differ before/after all these tests.
5. M3 must supply OS-restorable typed records and a startup/conflict-aware executor before revisiting the capture gate.
