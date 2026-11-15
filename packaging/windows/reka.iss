#ifndef SourceRoot
  #define SourceRoot "..\.."
#endif
#ifndef AppVersion
  #define AppVersion "1.0.0-dev"
#endif
#ifndef TargetArch
  #define TargetArch "x64compatible"
#endif
[Setup]
AppId={{B57C2E8B-C29B-4E5D-89B7-64EC8EB53C0A}
AppName=Reka proxy core
AppVersion={#AppVersion}
VersionInfoVersion=1.0.0.0
DefaultDirName={autopf}\Reka
ArchitecturesAllowed={#TargetArch}
ArchitecturesInstallIn64BitMode={#TargetArch}
PrivilegesRequired=admin
OutputBaseFilename=reka-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
LicenseFile={#SourceRoot}\LICENSE
UninstallDisplayName=Reka proxy core
[Files]
Source: "{#SourceRoot}\reka.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\rekactl.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\packaging\windows\*.ps1"; DestDir: "{app}\packaging\windows"; Flags: ignoreversion
Source: "{#SourceRoot}\packaging\windows\WINTUN-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\licenses\*"; DestDir: "{app}\licenses"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\MODULES.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\BUILD.json"; DestDir: "{app}"; Flags: ignoreversion
[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\packaging\windows\install.ps1"""; Flags: waituntilterminated runhidden; Description: "Install Reka service"
[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\packaging\windows\uninstall.ps1"""; Flags: waituntilterminated runhidden
