; Inno Setup script for the ADBlock Windows web server.
; Build: iscc.exe installer.iss   (output: dist-installer\adblock-webserver-setup.exe)
[Setup]
; Stable identity so an upgrade replaces the previous install (and keeps its
; folder as the default) instead of installing side by side.
AppId={{8F2A61D4-6C0B-4B3E-9E77-ADB10C1A5F27}
AppName=ADBlock 拦截服务器
AppVersion=1.75
AppPublisher=wxcvm
DefaultDirName={code:PreferredInstallDir}
DefaultGroupName=ADBlock
DisableProgramGroupPage=yes
; Never skip the destination page: on an upgrade Inno hides it, so the folder
; could not be changed (only /VERYSILENT skips it now).
DisableDirPage=no
UsePreviousAppDir=yes
OutputDir=dist-installer
OutputBaseFilename=adblock-webserver-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
WizardStyle=modern
; A running webserver.exe would lock its files: let Inno close it (and the
; code below kills it explicitly as well, which also covers the tray process).
CloseApplications=force
RestartApplications=no

[Languages]
Name: "chinese"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"
Name: "autostart"; Description: "开机自动启动"; GroupDescription: "附加任务:"; Flags: unchecked

[Files]
; Program files are always replaced, but the resources folder is USER DATA:
; it holds the CA (.crt/.key), statistics (*.dat), the exported rule files
; (blocklist.txt / cosmetic.css), allowlist.txt, webserver.ini side files and
; any custom block image. Never overwrite those on an upgrade
; (onlyifdoesntexist), so updating keeps the certificate and the statistics.
Source: "dist\*"; DestDir: "{app}"; Excludes: "resources\*"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "dist\resources\*"; DestDir: "{app}\resources"; Excludes: "localhost-2410.*,localhost-leaf.*,*.dat,stats.json,update_cache.json,control_token.txt,ca_rotation.json,webserver.log,webserver.log.1,crash.log,allowlist.txt,blocklist.txt,cosmetic.css"; Flags: recursesubdirs createallsubdirs onlyifdoesntexist

[Icons]
Name: "{group}\ADBlock 仪表盘"; Filename: "{app}\webserver.exe"; WorkingDir: "{app}"; Parameters: "--resources ""{app}\resources"""
Name: "{group}\卸载 ADBlock"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ADBlock"; Filename: "{app}\webserver.exe"; WorkingDir: "{app}"; Parameters: "--resources ""{app}\resources"""; Tasks: desktopicon


[Run]
; Register autostart through the application's own HKCU Run key. A Startup
; folder shortcut (as before) plus that Run key meant TWO autostart entries and
; therefore two server processes after logon.
Filename: "{app}\webserver.exe"; Parameters: "--install-autostart"; Tasks: autostart; Flags: runhidden skipifsilent
Filename: "{app}\webserver.exe"; Parameters: "--resources ""{app}\resources"""; WorkingDir: "{app}"; Description: "安装完成后立即启动 ADBlock"; Flags: nowait postinstall skipifsilent
; The in-app updater installs with /VERYSILENT. Every entry above is skipped in
; that mode (skipifsilent) and RestartApplications=no keeps Inno from bringing
; the server back either, so the update killed the running dashboard and left
; nothing behind - it looked like "更新失败". Start it again for the silent path.
Filename: "{app}\webserver.exe"; Parameters: "--resources ""{app}\resources"""; WorkingDir: "{app}"; Flags: nowait; Check: WizardSilent

[UninstallRun]
Filename: "{app}\webserver.exe"; Parameters: "--uninstall-autostart"; Flags: runhidden skipifdoesntexist

[Code]
{ The default is D: when available; the user can always choose another
  location in the destination wizard. Existing installs retain their previous
  location because UsePreviousAppDir=yes. Do not assume D: exists in CI/VMs. }
function PreferredInstallDir(Param: String): String;
begin
  if DirExists('D:\') then
    Result := 'D:\ADBlock'
  else
    Result := ExpandConstant('{localappdata}\Programs\ADBlock');
end;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
  Pid: String;
begin
  { An updater may supply a PID for the running instance being upgraded.
    NEVER kill *all* webserver.exe processes: other stable/preview instances
    may live in a different directory, and killing by basename is unsafe.
    Inno CloseApplications can handle the current installation's files. }
  Pid := ExpandConstant('{param:PID|}');
  if Pid <> '' then
    Exec('taskkill.exe', '/F /PID ' + Pid, '', SW_HIDE,
         ewWaitUntilTerminated, ResultCode);
  Result := True;
end;
