# Loopback-only DNS TCP diagnostic

`dns-loopback-probe.exe <hosts-or-abp-file> <loopback-port> [budget-ms]`

This separate inspection tool imports one explicit local source through the
real bounded subscription importer, stages typed records and builds the actual
production rule snapshot. It evaluates only `example.com IN A`. A local block
or supported replacement is synthesized before opening any network socket.
An unmatched/allow query contacts **127.0.0.1 at the supplied port only**.
No name resolution or external resolver selection is performed by the tool.

The tool sends UDP first. Only a matching, complete fixed question and a TC
header trigger one TCP retry to the same loopback port. TCP uses two-byte length
framing, handles split prefix/body reads and retains the original 512-byte cap.
Malformed, short, oversized or still-truncated TCP responses fail without an
answer. A single 1..1200 ms budget covers both transports. Timeouts and invalid
UDP data are failures rather than unbounded retries.

`dns_probe_resolve` also accepts a caller-owned cancellation event; nonblocking
socket waits observe it, close their sockets and return `DNS_PROBE_CANCELLED`.
Decision metadata is copied from one production generation before I/O. JSON
contains status, local/UDP/TCP path, byte count and local rule provenance; it
does not print input paths, subscription URLs or system network configuration.

The reply contract and 23 vectors are independently fixed at Android commit
`6f1f9c69a2513a4ccb18b8da90f0c8527ab6f955` by `fetch-dns-contract.sh`.
Its cache has a file SHA-256 manifest. Existing production portable core and
shared rule-contract pins are unchanged; this tool is a separate CI artifact,
not linked into or enabled by the default GUI/server package.

CI tests real loopback UDP/TCP fixtures with 12 importer-to-socket scenarios,
split frames, malformed replies, total deadline and rule-before-network paths.
Eight native TCP cancellation cycles verify the peer sees connection closure.
Fixtures use temporary files, bind ephemeral loopback ports and stop all worker
threads; no daily-host installation, DNS settings, route, TUN or WFP changes.

The 512-byte bound, fixed query and one-shot connections make this a diagnostic,
not a full resolver, cache, DNSSEC implementation or network capture backend.
Windows driver/routing/recovery acceptance and Android real protect/bind behavior
remain separate. TCP framing/retry reference: [RFC 7766 sections 4 and 8](https://www.rfc-editor.org/rfc/rfc7766.html).
