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
The app table uses Mongoose to iterate complete top-level app objects; nested
host counters no longer become phantom `id 0` applications or hide the final
pinning flag. The actual GUI decoder is compiled in a separate regression
fixture covering nested hosts, counters, flags, ordering and array boundaries.

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
# HTTP 连接协议与响应分类

日志保留原有动作筛选，现有组合框还可选择 IPv4、IPv6、未知协议，或图片、脚本、样式等响应处理分类；一次选择一个维度，与全部保留历史的服务器端域名／路径／状态搜索组合。协议来自实际 HTTP socket，不能通过 Host 名称、冒号或 DNS A/AAAA 推断。旧记录缺少协议时保留未知；分类描述响应处理策略，不是订阅规则来源。

统计 JSON 和日志页面独立读取、独立发布。统计读取失败保留上一份统计并显示过期状态，同时继续更新可读取的日志；日志失败或翻页过期则保留已有记录。无有效统计时仍可浏览已成功取得的日志。

## Versioned full retained-history evidence

New clients request filterVersion=1. Server filtering includes optional action/family/type/uid/q; q is at most191 UTF-8 bytes, ASCII-folded for matching while other UTF-8 bytes remain exact. Each query is bound by SHA256 queryKey plus generation/anchor. total/offset/nextOffset count matching rows; retainedTotal explains the bounded retained history. An absent capability is an explicit service-upgrade error, never a fallback to filtering only the visible page. Existing clients retain their unversioned semantics.

Rows preserve actual observed family, bounded path without query/fragment, queued local status, truncation and decimal sequence identity within one generation. QLG/QLG2 legacy rows keep unknown metadata; QLG3 is staged and validated before replacing current rows. Local access refusals are action3, separate from policy block1. A queued status does not prove client receipt, browser rendering, upstream completion or AdGuard provenance.

The existing worker handles immutable filter revisions and full fixed-snapshot CSV export with progress/cancel. It writes a unique staging file and atomically publishes only a complete snapshot; failed, expired or cancelled exports do not become apparently complete outputs. New request counters are attributed before proxy/exemption returns and SNI excludes management polling. Connection counts mean connections carrying observed Web traffic, not all accepted sockets.

Shared query-log source is pinned independently toc1533839fe5b8cd814d3a0b8653859a4bba05b58 with exact file hashes. Production portable core4470606366e614abdb308fdfe94734d28167439c remains unchanged; count-checked overlays add response metadata and filtered history. Windows memory/persistence4096, summary400 and page49152-byte limits are unchanged. No user host DNS/Hosts/trust/AdGuard changes.
