# Windows progress preview installation

This is a progress inspection build. Choose one of these routes:

| Route | Artifact | Scope |
|---|---|---|
| Normal install | `adblock-preview-user-x64.exe` | Current user; no administrator account required |
| All users | `adblock-preview-machine-x64.exe` | Program Files; asks for administrator approval |
| Portable | `adblock-webserver-win64.zip` | Extract into a new writable folder, run `start-preview.bat` |
| PowerShell | `install-preview.ps1` | Downloads this exact release, checks its embedded SHA-256, then uses one of the three routes above |

PowerShell examples after downloading and inspecting the script:

```powershell
.\install-preview.ps1 -Method User
.\install-preview.ps1 -Method Machine
.\install-preview.ps1 -Method Portable -InstallDirectory "$env:LOCALAPPDATA\ADBlockPreviewPortable"
```

GitHub CLI users can also download the portable package with
`gh release download <progress-tag> -R wxcvm/AdAway-Windows -p adblock-webserver-win64.zip`.
No winget/Chocolatey/Store registration is claimed by this release.

Preview installers use their own AppId, installation directory and shortcuts.
They do not stop a running production process, register autostart, install a
CA or automatically run the server after installation. Shortcuts and
`start-preview.bat` bind loopback only, with HTTP 18080, HTTPS 18443 and
management 18686. In-app production updating is disabled in the preview
binary. Closing the preview stops its listener; it does not represent OS
route/DNS recovery or global capture.

The v1.75 UI inspection installer and its embedded webserver.exe are
**unsigned**. On Windows 11 with Smart App Control in enforcement mode,
the installer may be blocked before any dialog or log is created. There
may be **no** "More info" override. Do not disable Defender, SmartScreen
or Smart App Control for this preview. An unsigned portable build may
also be blocked by the same policy; it is an alternative diagnostic,
not a security workaround.

To distinguish a damaged download from an unsigned-app block, check the
release SHA256SUMS and the Windows Security > Protection history, then
Windows Security > App & browser control > Smart App Control settings.
The read-only script `tools/diagnose-preview-installer.ps1` reports
the SHA-256 hash, Authenticode signature state and relevant recent Code
Integrity events. It does not execute the installer or alter security settings.

Use the portable route only when Windows policy permits it and only if
you trust the release. Do not extract over an existing production folder.
Check `SHA256SUMS.txt` against downloaded files. The preview publication workflow requires the **same production Authenticode certificate** for the Windows webserver executable and BOTH preview installers. Publication fails if the prior production EXE is unsigned or the certificate differs. A checksum verifies downloaded bytes but does not replace publisher identity validation.
MSI, MSIX and public package-manager distribution remain future work.

Current implementation and incomplete platform acceptance are described in
`IMPLEMENTATION-STATUS.md`. Keep the original production installation/data;
this preview is not the production update feed.
