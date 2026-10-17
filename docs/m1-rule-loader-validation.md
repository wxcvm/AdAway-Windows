# M1-R1 Windows production subscription integration

Depends on Windows draft #4 and Android draft #48. No merge, release, Wintun
adapter, default route, DNS/OS change, CA installation or capture activation.

The actual dashboard subscription updater previously truncated
`subscriptions.txt` before downloading sources, flattened conditional ABP
rules into domains and reported failed downloads as "old result retained".
The updater now snapshots its source list, holds an exclusive transaction
file lock, downloads each source with a byte/time bound, parses complete
semantic rules to a separate file, flushes it, and atomically replaces the
last complete file only if every source succeeded. Any failure preserves the
entire previous dataset. Updates are all-or-nothing; there is no per-source
partial commit. Sources cannot be edited while an update is running.

The shared real parser preserves Hosts aliases, bare domains, ABP exceptions,
suffix scope and address replacement lines. URL/resource conditions remain
unsupported and are counted/skipped instead of broadened. Address replacement
lines do not mean HTTP blocking or successful forwarding. The dashboard
reports saved file state and a reload request, not verified active filtering.

The production C service remains pinned to
`4470606366e614abdb308fdfe94734d28167439c`. The independently fetched portable
loader/contract files are pinned in `fetch-core-contract.sh`. A strict source
SHA-256 guard generates a build-only overlay for domain normalization,
exemption lookup and the production subscription block-table functions. It
does not import the newer Android-only webserver source. Modified/unproven
source caches and any changed production source are rejected; cached source
files are not rewritten. The generated translation unit retains existing
Windows portability, service, GUI and capture gates.

Native decisions use one immutable sorted index/pool/generation. Full names
avoid hash-only false matches. Invalid/stale/failed updates preserve the old
table. Readers return copied decisions; concurrent publication does not
expose freed pointers or a mixed count/generation. Native HTTP filtering uses
the actual `block_set_contains` path, not an independent test-only helper.

## Bounds and tests

At most 32 sources, a 180-second group budget checked between operations,
64 MiB per download and per parsed output, 4,096 bytes per line, 500,000 merged
entries and a 32 MiB native name pool. WinHTTP's bounded subscription path
does not resume unverified partial responses. Its socket operations retain
the existing finite timeout; a blocking operation can outlast the remaining
group deadline until its socket timeout. Updater package resume behavior is
preserved separately. These are resource limits, not performance claims.

Local MSVC `/utf-8 /std:c11 /W4 /WX` tests cover shared fixtures, two native
four-reader/1,000-update/200,000-query tests, 300,000-entry actual loading, and
the real Windows file transaction with a mock download callback. The actual
transaction checks download failure, parse failure, lock contention, rename
failure due to an open reader, old-file preservation and complete success.
It uses private temporary files and makes no network or OS configuration
changes. Hosted Windows CI additionally runs MinGW tests, the real pinned
source acquisition/compatibility overlay, complete application/installer
build and existing loopback service smoke tests. Final HEAD-specific CI
evidence belongs in the draft PR and workspace report.

Remaining acceptance: no real subscription-network failure injection, physical
Android/Windows networking, production DNS synthesis, cache/network-generation
invalidation, protected TCP/UDP data plane or OS recovery is proven here.
Android's effective Java snapshot still needs the typed suffix/provenance
bridge documented in #48 before full M1-R1 cross-platform DNS acceptance.

Failure rollback keeps the previous subscription file and live rule snapshot;
staging files are removed on normal failure and never replayed on startup.
Unreferenced staging files after a hard process kill are not recovery intents.
No decrypted model or CI result authorizes capture or a system network change.
