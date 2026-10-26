# Isolated LWS feasibility on Windows

This branch does NOT change `build.sh`, the production portable-core pin, app version, install identity or update feeds. The original export/UI branch is separate. No production migration or application release is requested.

`tools/lws-spike/source.json` pins the shared Android prototype commit and exact Git tree. `fetch_source.py` downloads only the listed files, verifies canonical Git-blob SHA-256 and refuses modified caches. Shared logic is not independently rewritten for Windows. The prototype's own dependency lock pins LWS a842936f881921b6462b3328cce8e700b7a7ecd2, OpenSSL 3.5.9 and the Mongoose/image fixtures.

The standalone workflow builds real MinGW executables with the existing fixed OpenSSL builder, runs loopback HTTP/TLS/WebSocket and cache/lifecycle checks, then paired same-host benchmarks. It enables only the needed LWS protocols and uses documented LWS/OpenSSL certificate hooks without replacing LWS SNI handling. Upstream MinGW build warnings are retained in logs; adapter code uses strict warnings as errors.

Only JSON/logs are spike artifacts. No baseline Mongoose executable, CA private key, APK or installer is included. Working directories are under `.lws-spike/` and do not participate in the production build or packaging list. Existing unrelated production CI is not changed by this spike.

Status is **NO-GO for the current adaptation**: the independently collected full benchmark does not clear the reproduced forwarding failure. See [the final report](lws-feasibility-results-20261026.md) for exact source, CI and durable raw-data links. A successful fixture handshake is not a proof of all production qlog/statistics/UI/Root behavior, nor a claim of Android17 device acceptance. Missing capability checks and noisy measurements remain INCONCLUSIVE; the performance thresholds are <=15% stable regression and <=10% paired variation. Passing a prototype PR never enables production migration.

## Follow-up findings

The shared source now includes bounded controlled-loopback forwarding, cancellation, capacity recovery, oversized input, actual certificate-expiry renewal and explicit response differential checks. The Windows fixture must set `MG_ENABLE_POLL=1`, as the existing production `build.sh` does; the first spike accidentally selected Winsock select and generated 100 client errors at concurrency64. That earlier data is not a fair final performance comparison. Both fixtures use explicit test-CA trust rather than loading unused operating-system trust stores. Vendor warnings are preserved; adapters remain warnings-as-errors.

The Windows-owned `docs/lws-migration-inventory.json` lists 15 public Mongoose call names across six files, including GUI/qlog/updater JSON consumers and test helpers. The independently fixed production core in `fetch-upstream.sh` remains `4470606366e614abdb308fdfe94734d28167439c`. Replacing only the transport would not remove the JSON/HTTP parser dependency. See the Android feasibility report for the shared capability matrix, raw-data ledger, preliminary INCONCLUSIVE decision and indicative migration effort.

Corrected file-creation runtime evidence: [40201091707](https://github.com/wxcvm/AdAway-Windows/actions/runs/40201091707), source `7e8b6a472bd2e9f4ad9dd170c9c82a8e3e0f6df7` fetching Android `a5c9fd582f18993054ddf3bd2fe8b258968fe921`. This predates expanded forwarding/lifetime tests. Full earlier performance artifacts are preserved in [40196591111](https://github.com/wxcvm/AdAway-Windows/actions/runs/40196591111): 300 phases, 25/30 noisy groups, INCONCLUSIVE. No performance or migration GO is claimed; final frozen-source runs remain required.

## Current blocked capability

**NO-GO for this adaptation, not a production migration recommendation.** [40253927417](https://github.com/wxcvm/AdAway-Windows/actions/runs/40253927417) and normal/diagnostic [40254812604](https://github.com/wxcvm/AdAway-Windows/actions/runs/40254812604) reproduced plain IPv4 HTTP `/forward/text` with declared4096 bytes but only4018 delivered. This is not a TLS-name/CA rejection. The actual close/completion ordering still needs a public-interface solution; no private LWS field/patch or inflated buffer limit is used to hide it. Required correctness stays FAILED and this PR stays draft, unmerged.

Independent baseline and native positive/corrupt-body tests now continue after a backend failure, saving incomplete runs as `complete:false`. Manual paired measurements are rebuilt with diagnostic logging OFF and can run independently, but never convert the earlier required failure to success. Full measurements may inform future work; they cannot approve a migration with a reproducibly incomplete ordinary response.
