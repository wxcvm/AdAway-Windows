# Dashboard response validation

The dashboard previously treated any received bytes as a successful statistics
response. A 404/500 page or a body cut short by a timeout could stop management
port fallback, show invented zero counters, or replace the recent-request summary
with an empty failed query-log response.

`dashboard_response.h` reuses the already linked, pinned Mongoose implementation
to require HTTP/1.0 or 1.1 status 200, exactly one Content-Length, a complete
body, and no Transfer-Encoding or surplus bytes. Only the body reaches existing
field readers. Statistics additionally require a complete JSON object with
nonnegative integer uptime and total-request fields. Failed query-log responses
retain the summary from the same successful statistics fetch.

The polling worker compares all rendered snapshot fields except uptime before
notifying the UI. Changes limited to TLS failures, per-app data or request logs
therefore no longer depend on a later request-counter change or the 60-second
clock refresh. Signed arithmetic is no longer used as a change signature.

`dashboard_response_test.c` exercises the production helper against real
Mongoose, including every truncated prefix, 404/500, duplicate lengths,
overflowing lengths, chunked/ambiguous framing, embedded NULs, trailing bytes,
malformed JSON and invalid required counters. Local MSVC `/W4 /WX` compilation
and execution passed using Mongoose from production core commit
`4470606366e614abdb308fdfe94734d28167439c`. The workflow adds a strict MinGW run
using the same frozen dependency.

This is a focused response-validation change. Complete history pagination,
retaining stale displayed Windows snapshots, and subscription-page improvements
remain separate work. Full Windows executable CI and actual desktop acceptance
must be reported independently from these helper tests. No production portable
core pin, subscription semantics, update channel or installation identity changes.
