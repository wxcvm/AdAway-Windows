# Typed subscription provenance v1

Based on main 11bfa97 (v1.75 UI/installers/updater). Production portable core
4470606 and its SHA-256 guard remain unchanged. Only the independently pinned
portable rules/tests advance; the overlay still preserves Windows platform
and single-instance fixes.

Subscription refresh emits versioned typed records into the existing single
staged subscriptions.txt transaction. All sources must download and parse
successfully before replacement. Records contain local numeric source slot,
emitted entry order, action, exact/suffix/wildcard scope and optional literal
address. They contain no source URLs. Source IDs are 2 + configured list
position; reordering sources deliberately changes source tie order. ID 1 is
reserved for explicit local user rules, never assigned by remote import.
Old semantic files remain readable and matched records are marked legacy.
Do not downgrade to an older executable with a newly typed subscription file;
keep a backup of the prior installation/data when testing a development build.

Decision order matches the Android DomainRule contract: user first; otherwise
allow > replacement > block; then exact > suffix > wildcard, longer pattern,
lower source ID and earlier source entry. User ties instead take the latest
entry. Remaining ties use lexical domain/action/binary-address ordering.
ABP suffixes match only apex/label boundaries. Unsupported conditions remain
skipped; replacement family mismatch returns PASS/INVALID_DATA. Existing
manual HTTP exemption files are separate from subscription provenance.

Production bs_decide returns copied action/address/source/order/scope/legacy
and generation from one locked snapshot. The HTTP block hook only blocks
NXDOMAIN; address replacement is not misreported as successful HTTP forwarding.
dns_policy_respond_from_rules uses that same production decision for the
existing pure DNS encoder. It opens no listener or route and adds no cache.
Tests exercise actual subscription parsing -> serialized file -> production
snapshot -> DNS bytes, alongside the real Windows atomic update fault tests.

Exact and suffix queries use a sorted index and parent labels. Wildcard rules
use required literal-anchor buckets prepared once per generation. No query
unconditionally scans every rule. Existing 500k entry/32 MiB pool/64 MiB file
bounds remain; index/record metadata increases memory usage and is not a
measured device memory guarantee. Invalid, stale, malformed or failed updates
retain the previous published table. 26 shared query vectors compare scope,
action, address and provenance. Native input stays ASCII-only while Android
retains its IDN conversion; Unicode-source equivalence is not claimed.

PR CI builds the application and installers, runs strict native/transaction/
wire integration tests and isolated runner GUI smoke tests, and uploads build
artifacts. It does not publish a release or change the stable feed. Dedicated
device/Root/Windows route recovery and full forwarding acceptance remain open.
