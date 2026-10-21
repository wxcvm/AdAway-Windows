# Preview updates

On the Settings page choose **渠道：含预览版**, then **检查更新**. The separate
**包：安装器优先 / 包：ZIP 覆盖** control chooses how the same update is applied. The
installer preference retains its verified ZIP fallback. ZIP mode updates
the running folder directly. The chosen channel is persisted as
`[settings] include_preview=1` in `webserver.ini` beside the executable.

**自动更新：开启 / 关闭** independently controls whether a newly discovered update
is downloaded, checked and applied without another application confirmation.
When enabled, discovery starts one minute after launch and repeats every six
hours. Background no-change/failure results remain quiet; manual checks retain
their feedback. Windows administrator confirmation may still be required.
The path-scoped portable helper shipped in 1.83 is used by 1.83 and later;
an upgrade initiated from 1.82 still uses that old client's update implementation.

The default channel reads only `win11-latest/windows-manifest.json`. Opt-in checks
also read `win11-preview/windows-manifest.json` and compare both results. A stable
response cannot short-circuit preview discovery. The preview pointer contains the
numeric app version, CI build identity, immutable `progress-win-*` package URLs
and exact EXE/ZIP SHA-256 digests. Equal app versions compare build identities;
older stable versions never downgrade a preview. Caches are scoped by channel,
running version/build and package preference. Changing channel is disabled while
an update runs; stale preview offers are rejected after opting out.

The existing pinned Mongoose JSON parser reads complete release and asset objects,
preserving key-order independence and preventing a neighboring asset digest from
being used. No additional JSON or updater library is introduced. API fallback
skips drafts, auxiliary pointers and isolated preview packages. Production core
pin and overlays remain unchanged. Installation retains the production AppId.

Preview publication is serialized, updates only the independent opt-in pointer,
and refuses to overwrite a newer version/build. Stable pointers stay unchanged.
The repository's existing unsigned Windows distribution policy remains in effect;
hashes verify package integrity. Already installed clients need one manual upgrade
to this fix. CI installs only on a disposable runner, never on the user's host.
