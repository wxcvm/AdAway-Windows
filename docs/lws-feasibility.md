# Isolated LWS feasibility on Windows

This branch does NOT change `build.sh`, the production portable-core pin, app version, install identity or update feeds. The original export/UI branch is separate. No production migration or application release is requested.

`tools/lws-spike/source.json` pins the shared Android prototype commit and exact Git tree. `fetch_source.py` downloads only the listed files, verifies canonical Git-blob SHA-256 and refuses modified caches. Shared logic is not independently rewritten for Windows. The prototype's own dependency lock pins LWS a842936f881921b6462b3328cce8e700b7a7ecd2, OpenSSL 3.5.9 and the Mongoose/image fixtures.

The standalone workflow builds real MinGW executables with the existing fixed OpenSSL builder, runs loopback HTTP/TLS/WebSocket and cache/lifecycle checks, then paired same-host benchmarks. It enables only the needed LWS protocols and uses documented LWS/OpenSSL certificate hooks without replacing LWS SNI handling. Upstream MinGW build warnings are retained in logs; adapter code uses strict warnings as errors.

Only JSON/logs are spike artifacts. No baseline Mongoose executable, CA private key, APK or installer is included. Working directories are under `.lws-spike/` and do not participate in the production build or packaging list. Existing unrelated production CI is not changed by this spike.

Status is EVIDENCE INCOMPLETE until the pinned Windows build/runtime/performance data and Android/Linux evidence have been reviewed. A successful fixture handshake is not a proof of all production qlog/statistics/UI/Root behavior, nor a claim of Android17 device acceptance. Missing capability checks and noisy measurements remain INCONCLUSIVE; the performance thresholds are <=15% stable regression and <=10% paired variation. Passing a prototype PR never enables production migration.
