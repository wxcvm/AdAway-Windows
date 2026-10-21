# Query-log history and retained statistics

The old GUI requested `/internal-qlog`, but production portable core commit
`4470606366e614abdb308fdfe94734d28167439c` had no such endpoint. A larger GUI
array therefore still showed only the bounded 400-row statistics summary.

The portable core remains frozen and SHA-verified. A count-checked overlay adds
the gated management endpoint and includes only the separately pinned query-log
contract from Android commit `a56ce726a1eba201fdbf384280009943459e1410`. Acquisition
verifies commit, exact file list and SHA-256 hashes, preserving a changed cache.
Windows keeps its existing 4,096-entry memory/disk retention, 400-row summary and
49,152-byte page output cap. A page asks for up to 300 rows and uses actual
`returned` / `nextOffset`, since long hostnames can hit the byte cap first.

Generation and sequence anchor fix the history while scrolling or paging.
Previous uses remembered actual offsets; refresh returns to the latest head.
Restart, clear and overwritten history expire the cursor. A revision taken
under the dashboard mutex prevents an older request from replacing a newer
navigation choice. Reads run in the worker; buttons wake it immediately.
Failures retain displayed rows, explain the failure and permit refresh.
The UTF-16 display buffer holds every hostname supported by the 191-byte log
contract; the drawing surface adds an ellipsis when a name exceeds its width.

Control requests use the existing per-run token. The overlay corrects the old
boolean check of Mongoose's negative missing-variable result, so header-only
desktop clients reach the token-header fallback. Missing and wrong credentials
remain rejected, including a wrong form token paired with a valid header.

The production page parser reuses Mongoose, validates cursor, scalar types,
metadata consistency, row count and bounded UTF-8 hostnames, and publishes only
after complete staging. The pinned Mongoose string decoder supports limited
Unicode escapes; unsupported escaped non-ASCII input is rejected rather than
silently accepting a decoded prefix. Literal UTF-8 from the actual server stays
supported. This does not change rule normalization or platform IDN semantics.

Windows log persistence uses unique same-directory files, UTF-8-to-wide paths,
flush/commit/close and atomic replacement. Publication failure keeps the previous
file. Legacy ring files remain readable; new compact files retain newest order.
Statistics distinguish a live response from retained display data. A failed
refresh keeps the previous counters and records their observation time, while
service status remains disconnected. Initial unavailable values use a dash.

Long blocked hostnames also exposed an old statistics-JSON failure: a fixed
top-host buffer retained part of the last row. The overlay now rolls back
partial top/TLS/listener rows and incomplete app objects at existing limits,
and sanitizes app-host display metadata through the existing helper. The
shared fixture compiles the actual Android/Windows rendering blocks and checks
130 population/metadata scenarios with real Mongoose. Zero/failed clock reads
are skipped before altering the shared log ring, preserving valid history.

DeepSeek Flash Max drafted the page parser and its tests with complete relevant
public files and the provider/catalog default output cap. The draft passed its
first strict MSVC compile and tests. Maintainer review added the pinned-decoder
escape check and independent navigation, persistence and wire/GUI integration.
Model output alone is not validation evidence.

Local evidence: production parser and navigation passed MSVC `/W4 /WX` with real
frozen Mongoose; atomic storage passed UTF-8 filenames, replacement, locked-file
rollback and staging cleanup. CI adds strict MinGW, Linux ASan/UBSan, actual
server/client exchanges beyond 400 rows, bounded short pages, concurrent writes,
overwrite expiry, complete restart order/metadata and clear expiry. Real GUI
checks exercise history controls, expired-row retention and screenshots. Their
results remain pending until the exact submitted commit completes CI.

No system routing, DNS takeover, certificate installation or user-device install
is part of these tests. The executable fixture runs only on a disposable CI
runner with loopback listeners and owned temporary files.
