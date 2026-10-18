# Dashboard and rule workflow review (2026-10-18)

The dashboard retains the native Win32 application and existing network behavior. The UI now uses teal navigation and neutral cards, consistent light/dark surfaces, and character-height fonts with larger native control labels.

Settings group server configuration, response policy and maintenance. The duplicate listener card no longer paints beneath maintenance controls. The 1032 x 678 logical canvas includes rightmost controls, and font handles are replaced together with resized control bounds. Normal keyboard traversal includes edit fields and buttons.

Subscription controls follow job state and selection. Updating locks edits and repeated starts; list refresh preserves selection. Removal asks for confirmation and explains that existing imported rules remain until replacement. With no configured sources, an explicit confirmed action clears imported subscription rules through the same staged validation and atomic replacement transaction. A failed replacement retains the previous file. Statistics polling preserves the latest operation result instead of overwriting it every two seconds.

`tools/inspect-ui.ps1` runs against the real GUI in a disposable CI runner. It captures overview/settings/subscriptions in light and dark appearance, checks native control intersections, selection enablement, and font changes between compact and standard client dimensions. Hosted display bounds can prevent a 1548 px top-level window; the check records actual dimensions and does not claim multi-monitor DPI coverage. Screenshots and layout evidence are uploaded as `windows-ui-review`.

The local transaction regression verifies both explicit empty-source clearing and rollback when an open reader prevents replacement. Existing shared rule core pins and production portable-core overlay remain unchanged. No daily-host installation, CA trust, default routes, TUN or WFP activation is part of this UI change. The PR produces inspection artifacts only.
