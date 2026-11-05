# Update stage lifetime (1.93)

The EXE and portable routes share downloading and verification, not directory
reservation. Earlier versions created a sibling directory as a writability probe
before the route was known. Starting an EXE then returned without removing it.

Now download failure, digest rejection, EXE success/failure, ZIP-header failure
and listing rejection all exit before stage reservation. Archive listing uses a
temporary file in the existing package folder and deletes that file on return.
Only an accepted ZIP reserves its stage immediately before extraction.

CreateDirectoryW must create a fresh candidate. ERROR_ALREADY_EXISTS is not
ownership. Prefer an installation sibling on the same volume, fall back to the
existing system-temp/copy route if needed, and fail without deleting/reusing
colliding candidates. Do not delete/recreate a candidate before initial extraction.

Existing extraction cleanup and the PowerShell update/rollback helper remain.
A nonempty stage retained on a helper failure is recovery evidence, not an empty
EXE-update artifact. This change does not sweep old directories, cached installer
EXEs or user resources; no new background cleaner or process is added.

Tests compile the actual production EXE-prefix control flow and directory
reservation code with inert network/digest/UI/launch boundaries, using a real
disposable filesystem root. The archive-order guard checks that reservation is
after header/listing rejection. The existing portable helper tests separately
exercise actual process restart and rollback. The fixture does not run an
installer or mutate a production installation. Prior default source reproduces
the empty directory regression; fixed source passes 13 cases.

Old updater code still runs when it installs this version: the transition may
leave one old-style artifact. Only subsequent updates execute the repaired flow.
Use the preview installer directly to avoid that old automatic-updater path.
