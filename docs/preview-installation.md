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

Use the portable route first if you only want to inspect the UI. Do not
extract over an existing production folder. Check `SHA256SUMS.txt` against
downloaded files. Unless a publisher signature is present, Windows may show
the normal unknown-publisher prompt; a checksum does not establish publisher
trust. MSI, MSIX and public package-manager distribution remain future work.

Current implementation and incomplete platform acceptance are described in
`IMPLEMENTATION-STATUS.md`. Keep the original production installation/data;
this preview is not the production update feed.
