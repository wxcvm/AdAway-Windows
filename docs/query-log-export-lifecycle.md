# Fixed-history export lifecycle

Export uses the existing poll worker, not an extra HTTP poller. The selected
filter, generation, anchor, query key, total and retained total are captured
before entering the modal native Save dialog. A changed/expired history fails;
it is not silently replaced with newer history. Cancelling the chooser starts
no export. CommDlgExtendedError is not reported as user cancellation.

The atomic phase machine is shared by the worker and UI. Cancel wins only before
the RUNNING -> COMMITTING compare-and-swap. Once committing, the UI says saving is
finishing rather than promising rollback. All successful exports close, flush and
commit a same-directory staging file before MoveFileExW replaces the destination.
Failures and accepted cancellation remove only this task's recorded staging path.
A cleanup failure blocks a new export until that path is confirmed absent. The
recheck does not delete a possibly replaced file and never discards the old path.
Progress fields are read as a mutex-protected snapshot, not raced against writes.

The phase regression uses Windows atomics and 1000 real-thread cancel/commit
races. The test-only GUI driver links the same shared GUI source manifest as
production and calls adblock_gui_run with owns_server=false. It has no production
CLI/environment test hooks and is outside the release distribution. The Python
controller checks PID and root owner before operating every dialog/control. It
uses a real production loopback service for Unicode, complete multi-page CSV,
native chooser cancellation and overwrite confirmation/refusal. A separate
controlled loopback HTTP peer holds a later page deterministically for cancellation
and expires history while the chooser is open. Reopen and zero-match cases are
also executed. No adapter, route, certificate store, autostart or updater action
is triggered; automatic update is disabled in the driver's own temporary INI.

A passing state-machine test is not GUI acceptance. Actual driver execution is
required in Windows CI. Locked destination, write/cleanup fault injection and the
commit boundary at the actual filesystem still require separate evidence; do not
claim them from phase tests. The portable core and independent contract pins are
unchanged; no application version or stable feed is advanced by this branch.
