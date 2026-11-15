# Isolated installer acceptance: refuse pre-existing production service/state.
param([Parameter(Mandatory=$true)][string]$Root,
      [ValidateSet('amd64','arm64')][string]$Arch='amd64')
$ErrorActionPreference='Stop'
$Root=[IO.Path]::GetFullPath($Root)
$app=Join-Path $env:ProgramFiles 'RekaAcceptance\installer'
$state=Join-Path $env:ProgramData 'Reka'
$setup=Join-Path $Root ("installer-$Arch\reka-1.0.0-dev-setup.exe")
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if(Get-Service Reka -ErrorAction SilentlyContinue){throw 'Existing Reka service must be preserved'}
if(Test-Path $state){throw 'Existing Reka state must be preserved'}
if(Test-Path $app){throw 'Acceptance app directory already exists'}
$report=[ordered]@{fresh_install=$false;upgrade=$false;uninstall=$false;state_retained=$false}
function RunSetup([string]$Log) {
    $p=Start-Process $setup -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/OWNERSID='+$owner),('/DIR="'+$app+'"'),('/LOG="'+(Join-Path $Root $Log)+'"')) -Wait -PassThru
    if($p.ExitCode -ne 0){throw "Installer exit $($p.ExitCode)"}
}
function Status {
    $result=& (Join-Path $app 'rekactl.exe') -c pipe://reka-service -json status
    if($LASTEXITCODE -ne 0){throw 'Owner control connection failed'}
    $result|ConvertFrom-Json
}
try {
    RunSetup 'installer-fresh.log'
    $first=Status
    if($first.runtime.network.mode -ne 'off'){throw 'Fresh service unexpectedly captures networking'}
    $commandBefore=(Get-CimInstance Win32_Service -Filter "Name='Reka'").PathName
    if($commandBefore -notmatch [regex]::Escape($owner)){throw 'Fresh service owner does not match installer user'}
    $report.fresh_install=$true
    $change=Join-Path $Root 'installer-local.yaml'
    'log: {level: warn}'|Set-Content -Encoding ASCII $change
    $commit=& (Join-Path $app 'rekactl.exe') -c pipe://reka-service -json commit -local $change -yes
    if($LASTEXITCODE -ne 0){throw 'Could not seed durable config before upgrade'}
    $before=Status
    $marker=Join-Path $state 'installer-acceptance-marker.txt'
    'retain-this-state'|Set-Content -Encoding ASCII $marker
    RunSetup 'installer-upgrade.log'
    $after=Status
    $commandAfter=(Get-CimInstance Win32_Service -Filter "Name='Reka'").PathName
    if($before.revision -ne $after.revision -or $commandBefore -ne $commandAfter){throw 'Upgrade changed revision or service owner/state command'}
    if(!(Test-Path $marker)){throw 'Upgrade removed state'}
    $report.upgrade=$true
    $report.revision_before=$before.revision;$report.revision_after=$after.revision
    $report.owner_preserved=$true
    $prepare=Join-Path $app 'packaging\windows\prepare-upgrade.ps1'
    $wrongOwner=if($owner -eq 'S-1-5-18'){'S-1-5-19'}else{'S-1-5-18'}
    $wrong=Start-Process 'powershell.exe' -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"'+$prepare+'"'),'-BinDir',('"'+$app+'"'),'-OwnerSID',$wrongOwner) -RedirectStandardOutput (Join-Path $Root 'owner-refused.out') -RedirectStandardError (Join-Path $Root 'owner-refused.err') -Wait -PassThru
    if($wrong.ExitCode -eq 0 -or (Get-Service Reka).Status -ne 'Running'){throw 'Owner-changing upgrade was accepted or stopped the service'}
    $report.owner_change_refused=$true
    $p=Start-Process (Join-Path $app 'unins000.exe') -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+(Join-Path $Root 'installer-uninstall.log')+'"')) -Wait -PassThru
    if($p.ExitCode -ne 0){throw "Uninstaller exit $($p.ExitCode)"}
    if(Get-Service Reka -ErrorAction SilentlyContinue){throw 'Uninstall left service registered'}
    if(Test-Path (Join-Path $app 'reka.exe')){throw 'Uninstall left installed binary'}
    $report.uninstall=$true
    $report.state_retained=Test-Path $marker
} catch {$report.error=$_.ToString()}
finally {
    $report.passed=$report.fresh_install -and $report.upgrade -and $report.uninstall -and $report.state_retained
    $report|ConvertTo-Json -Depth 10|Set-Content -Encoding UTF8 (Join-Path $Root 'installer-runtime.json')
    Get-Content (Join-Path $Root 'installer-runtime.json')
}
if(!$report.passed){throw 'Installer acceptance failed; state and logs retained for diagnosis'}
