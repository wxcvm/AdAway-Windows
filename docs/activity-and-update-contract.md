# Activity, subscriptions and application updates

The activity workspace uses the server's real query-log history. The request
list has its own scrolling area, domain search, action filter, readable details,
pause/resume and stable paging. Application counters have a separate view.
Search and action filters apply to the **loaded page**, not all retained history.
Scrolling or inspecting requests freezes history; refresh/resume returns to the
latest page. Failed reads and expired cursors preserve the previous visible data.

Statistics and log endpoints are read and published independently by the same
worker. Failed statistics retain old counters marked stale while a new log page
can still publish. Log failures/expired cursors keep the previous page, and a
navigation revision change rejects an in-flight old page.

New records expose observed connection family (IPv4, IPv6, or unknown). The
existing filter selector supports connection family and response classification
as well as action; domain search combines with that selection over the loaded
page. A Host that looks like IPv6 does not make an IPv4 socket an IPv6 request.
Legacy QLOG rows load with unknown family; the pinned QLG2 contract persists new
metadata without changing retention limits. Classification is the native
response-policy hint, not a subscription rule or DNS question type.

These are HTTP response-server observations. They do not count DNS/Hosts blocks
that never reach this server, decrypted HTTPS content, or third-party AdGuard
traffic. A local exemption returning no content is not successful origin access.
A forwarding-started record is not upstream completion. Missing process identity,
rule/source identity or unsupported response codes remain explicitly unknown.

The subscription workspace derives a name from the URL's host and final path
component, including GitHub owner/repository context. An explicit local name,
including `raw`, is preserved. Names are UTF-8 `# name:` comments preceding their
unchanged URL in `subscription_urls.txt`, so existing comment-skipping readers
remain compatible. Names and URLs commit together under the existing source
settings lock. Invalid, excessive or corrupt source files cannot be silently
truncated and overwritten. Rename, restore and removal failures retain the old
file and input. Names do not change rule content or download addresses.

Addresses omit userinfo, query and fragment by default. Showing the original
address requires the explicit full-address action. This display uses the existing
system WinHTTP parser, with additional HTTP(S), encoding and bounds checks; it
does not decode escapes or change subscription semantics. See the official
[WinHttpCrackUrl contract](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpcrackurl).

Automatic application updating is enabled by default and can be disabled. It
checks the selected channel one minute after launch and then every six hours.
Checks share the existing single updater state; background failures/no-change
results do not open dialogs. Package selection (installer first or ZIP in place)
is independent of automatic updating. Version, channel and digest checks remain
in the real download/apply path. Preview updates retain the production AppId and
do not advance the stable feed.

The portable helper validates absolute, nonoverlapping installation and staging
paths, rejects reparse points, and preserves the resource tree and settings. It
waits for this installation to exit, switches directories and restarts the exact
executable. Rollback only stops the process that this helper started, preserving
other installations with the same executable name. Its startup health check is
**five-second survival of that exact process**, not HTTP/listener readiness.
Inno may still need Windows administrator confirmation when permissions require it.

Policy changes use a separate atomic save and exclusive writer lock. Failed
publication preserves the old configuration and does not request a reload.
A reload acknowledgement is reported separately from confirmed active settings.

CI exercises disposable installations and controlled loopback requests. Real
Windows network capture/restoration, device certificates and third-party traffic
remain separate acceptance work. The production portable-core pin stays fixed;
new request-log host extraction is applied through a count-checked overlay and
an independently fixed shared contract.
