; Inspection builds use their own identity and never stop a production process.
#ifndef MachineInstall
  #define MachineInstall 0
#endif
[Setup]
AppId={{B7B741A8-D763-4B3C-A5DC-302A38AF9E7F}
AppName=ADBlock Preview
AppVersion=1.75
AppVerName=ADBlock Preview 1.75 (UI inspection)
AppPublisher=wxcvm
#if MachineInstall
DefaultDirName={code:PreferredPreviewDir}
PrivilegesRequired=admin
OutputBaseFilename=adblock-preview-machine-x64
#else
DefaultDirName={code:PreferredPreviewDir}
PrivilegesRequired=lowest
OutputBaseFilename=adblock-preview-user-x64
#endif
DefaultGroupName=ADBlock Preview
DisableProgramGroupPage=yes
DisableDirPage=no
UsePreviousAppDir=yes
OutputDir=dist-installer
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
CloseApplications=no
RestartApplications=no

[Files]
Source: "dist\*"; DestDir: "{app}"; Excludes: "resources\*"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "dist\resources\*"; DestDir: "{app}\resources"; Flags: recursesubdirs createallsubdirs onlyifdoesntexist

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Icons]
Name: "{group}\ADBlock Preview"; Filename: "{app}\webserver.exe"; WorkingDir: "{app}"; Parameters: "--resources ""{app}\resources"" --bind loopback --http-port 18080 --https-port 18443 --stats-port 18686"
Name: "{group}\Uninstall ADBlock Preview"; Filename: "{uninstallexe}"
Name: "{autodesktop}\ADBlock Preview"; Filename: "{app}\webserver.exe"; WorkingDir: "{app}"; Parameters: "--resources ""{app}\resources"" --bind loopback --http-port 18080 --https-port 18443 --stats-port 18686"; Tasks: desktopicon


[Run]
Filename: "{app}\webserver.exe"; WorkingDir: "{app}"; Parameters: "--resources ""{app}\resources"" --bind loopback --http-port 18080 --https-port 18443 --stats-port 18686"; Description: "安装完成后立即启动 ADBlock Preview"; Flags: nowait postinstall skipifsilent

[Code]
function PreferredPreviewDir(Param: String): String;
begin
  if DirExists('D:\') then
    Result := 'D:\ADBlockPreview'
  else
#if MachineInstall
    Result := ExpandConstant('{autopf}\ADBlockPreview');
#else
    Result := ExpandConstant('{localappdata}\Programs\ADBlockPreview');
#endif
end;

// No process killing, autostart registration, or silent CA installation.
