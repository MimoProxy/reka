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
CloseApplications=no
Compression=lzma2
SolidCompression=yes
LicenseFile={#SourceRoot}\LICENSE
UninstallDisplayName=Reka proxy core
[Files]
Source: "{#SourceRoot}\packaging\windows\prepare-upgrade.ps1"; Flags: dontcopy
Source: "{#SourceRoot}\reka.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\rekactl.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\packaging\windows\*.ps1"; DestDir: "{app}\packaging\windows"; Flags: ignoreversion
Source: "{#SourceRoot}\packaging\windows\WINTUN-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\licenses\*"; DestDir: "{app}\licenses"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "{#SourceRoot}\MODULES.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\BUILD.json"; DestDir: "{app}"; Flags: ignoreversion
[Code]
function OwnerParameter(): String;
var SID: String; Index: Integer;
begin
  Result := '';
  SID := ExpandConstant('{param:OWNERSID|}');
  if SID = '' then Exit;
  if Copy(SID, 1, 2) <> 'S-' then RaiseException('OWNERSID must be a Windows user SID.');
  for Index := 3 to Length(SID) do
    if Pos(Copy(SID, Index, 1), '0123456789-') = 0 then
      RaiseException('Invalid OWNERSID.');
  Result := '-OwnerSID "' + SID + '"';
end;

function RunServiceScript(ScriptPath, Parameters: String): Boolean;
var Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath + '" ' + Parameters,
    '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Result and (Code = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  ExtractTemporaryFile('prepare-upgrade.ps1');
  if not RunServiceScript(ExpandConstant('{tmp}\prepare-upgrade.ps1'),
    '-BinDir "' + ExpandConstant('{app}') + '" ' + OwnerParameter()) then
    Result := 'Could not prepare the Reka service. Its installation directory must match the selected directory.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    if not RunServiceScript(ExpandConstant('{app}\packaging\windows\install.ps1'),
      '-Upgrade -BinDir "' + ExpandConstant('{app}') + '" ' + OwnerParameter()) then
      RaiseException('Reka files were installed, but service setup failed. See packaging\windows\install.ps1.');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    if not RunServiceScript(ExpandConstant('{app}\packaging\windows\uninstall.ps1'), '') then
      RaiseException('Could not stop the Reka service; files have not been removed.');
end;
