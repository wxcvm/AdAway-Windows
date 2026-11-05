# Preview changes

## Windows 1.90 — source time-window comparison and import hardening
- After importing a Filtering Log JSON, choose **来源对照／诊断** for a 15-minute, 1-hour or 24-hour UTC window anchored to the newest imported event. The popup presents the imported AdGuard event/block counts next to **only the currently loaded AdAway HTTP history page** in that same absolute time window.
- Show when the local page is unavailable; label search and pagination boundaries, rather than treating zero observations as a full-machine zero.
- Do not infer one-to-one request matching, coverage percentage, leak rate, end-to-end latency, or all-source block totals. The two sources have no verified shared request identifier.
- Validate native cancel, malformed input, oversized files, replacement on re-import and volatile snapshot clearing after a full process restart; parser tests also cover empty exports, invalid UTF-16 escapes and long hostnames. A valid `LogRecords: []` import now replaces the previous snapshot with zero rows; malformed files retain the previous snapshot.
- This remains a manual, privacy-reduced import. There is no AdGuard live-log API integration or silent traffic collection.

## Windows 1.90 — unified log center and AdGuard offline import
- Combine the Windows native local request log, per-process activity and local block-host ranking under 日志中心.
- Display timestamp-sorted local request rows without changing the underlying pagination, snapshot evidence or CSV export semantics.
- Import a user-selected AdGuard Filtering Log ProtocolVersion 1 JSON using the Windows Open dialog. This is an explicit, read-only, memory-only snapshot; it does not continuously monitor AdGuard.
- Keep AdGuard block events and AdAway local HTTP response-server blocks in separate source views and ranked counts. DNS and TCP records are observations, not automatically deduplicated end-user requests.
- Display the original timestamp/UTC offset, request outcome, protocol, process basename, remote endpoint, matched rule and optional DPI/stealth flags. Do not retain cookies, HTTP headers, raw URLs, full file paths, DNS answers or the raw JSON.
- Cover the import parser and native GUI source-switch, detail, privacy and existing-export behavior with synthetic test fixtures.

## Windows 1.90 — fixed export context
- Freeze filters, generation/anchor/queryKey, expected matches and retained count before opening Save.
- After confirming the path, the worker reads its own copied export task rather than scattered shared navigation variables.
- Per-task progress IDs reject stale progress and terminal errors; cleanup paths remain separate mutable state under the existing mutex.
- Existing file transactions, atomic replacement, cancellation/committing boundary, CSV format and history-expiry rules remain unchanged.
- Preview notes and attachment share this summary with generated source/CI metadata; outdated PR builds are cancelled.

## Installation and acceptance boundaries
The installer uses production AppId **{8F2A61D4-6C0B-4B3E-9E77-ADB10C1A5F27}** and upgrades the existing installation, preserving settings/resources. No parallel preview app is added.
EXE, portable ZIP and SHA-256-pinned PowerShell installer are provided. MSI/MSIX/package-manager registration is not included.
Windows distributions currently remain **unsigned**: SHA-256 establishes download integrity, not an Authenticode publisher identity.
The preview pointer is opt-in; stable update sources are unchanged. No LWS migration, DNS/network takeover, host network/certificate modification or Android device installation is included.
