# Dashboard and rule workflow review (2026-10-18)

The dashboard retains the native Win32 application and existing network behavior. The UI now uses teal navigation and neutral cards, consistent light/dark surfaces, and character-height fonts with larger native control labels.

Settings group server configuration, response policy and maintenance. The duplicate listener card no longer paints beneath maintenance controls. The 1032 x 678 logical canvas includes rightmost controls, and font handles are replaced together with resized control bounds. Normal keyboard traversal includes edit fields and buttons.

Subscription controls follow job state and selection. Updating locks edits and repeated starts; list refresh preserves selection. Removal asks for confirmation and explains that existing imported rules remain until replacement. With no configured sources, an explicit confirmed action clears imported subscription rules through the same staged validation and atomic replacement transaction. A failed replacement retains the previous file. Statistics polling preserves the latest operation result instead of overwriting it every two seconds.

`tools/inspect-ui.ps1` runs against the real GUI in a disposable CI runner. It captures overview/settings/subscriptions in light and dark appearance, checks native control intersections, selection enablement, and font changes between compact and standard client dimensions. Hosted display bounds can prevent a 1548 px top-level window; the check records actual dimensions and does not claim multi-monitor DPI coverage. Screenshots and layout evidence are uploaded as `windows-ui-review`.

The local transaction regression verifies both explicit empty-source clearing and rollback when an open reader prevents replacement. Existing shared rule core pins and production portable-core overlay remain unchanged. No daily-host installation, CA trust, default routes, TUN or WFP activation is part of this UI change. The PR produces inspection artifacts only.

The UI runner uses a complete temporary installation copy, so fixture subscription URLs and persisted test appearance/port preferences cannot reach distribution files. Packaging rejects known fixture URLs and a smoke-test webserver.ini before archiving.


## Rule/source management follow-up

Source URL and status files now use a bounded UTF-8 staged write, flush/commit and atomic replacement. Failed source saves keep the previous file, UI list and typed input; source deletion restores its in-memory entry if persistence fails. A shared settings lock prevents competing file writes. Status cache writes use the same atomic helper. URL path case is retained when checking duplicate entries. UTF-8 byte buffers accommodate the existing 1024-wide-character limit without increasing that character bound.

The real GUI inspection holds an open reader to deny source-file replacement, attempts an add, and checks that the list/file/input remain unchanged. It then releases the reader, retries and verifies that both file and list commit and the input clears. The fixture stays in the temporary installation copy, with screenshots for both outcomes. A separate strict C test covers UTF-8, lock and replace failure, newline injection rejection and empty settings saves.

Cross-process edit automation uses bounded WM_SETTEXT / WM_GETTEXT messages; GetWindowText/SetWindowText are caption APIs with cross-process control limitations. All injected save commands have a 10-second bound and the GUI CI step has its own timeout.
