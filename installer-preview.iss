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
DefaultDirName={autopf}\ADBlockPreview
PrivilegesRequired=admin
OutputBaseFilename=adblock-preview-machine-x64
#else
DefaultDirName={localappdata}\Programs\ADBlockPreview
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

[Icons]
Name: "{group}\ADBlock Preview"; Filename: "{app}\webserver.exe"; WorkingDir: "{app}"; Parameters: "--resources ""{app}\resources"" --bind loopback --http-port 18080 --https-port 18443 --stats-port 18686"
Name: "{group}\Uninstall ADBlock Preview"; Filename: "{uninstallexe}"

; No process killing, autostart registration, CA installation or post-install launch.
