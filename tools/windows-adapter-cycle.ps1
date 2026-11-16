# Executed inside a local scheduled task so SSH loss cannot kill restoration.
param([Parameter(Mandatory=$true)][string]$InterfaceGuid,
      [Parameter(Mandatory=$true)][string]$Work)
$ErrorActionPreference='Stop'
$guid=[guid]$InterfaceGuid
function Adapter { @(Get-NetAdapter | Where-Object {[guid]$_.InterfaceGuid -eq $guid}) }
$adapter=@(Adapter)
if($adapter.Count -ne 1 -or $adapter[0].Status -ne 'Up'){throw ('Expected exactly one already-Up physical adapter; guid='+$guid+' count='+$adapter.Count+' states='+($adapter.Status -join ','))}
$restore=Join-Path $Work 'restore-adapter.ps1'
$task='RekaAcceptance-Restore-'+[guid]::NewGuid().ToString('N')
$body="`$ErrorActionPreference='Stop';Get-NetAdapter | Where-Object { [guid]`$_.InterfaceGuid -eq [guid]'$guid' } | Enable-NetAdapter -Confirm:`$false"
$body|Set-Content -Encoding ASCII $restore
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$restore+'"')
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Force|Out-Null
try {
    $adapter[0]|Disable-NetAdapter -Confirm:$false
    Start-Sleep -Seconds 8
    $disabled=@(Adapter)
    if($disabled[0].Status -ne 'Disabled'){throw 'Physical adapter did not enter Disabled state'}
    Write-Output ('Physical adapter Disabled: '+$guid)
} finally {
    Adapter|Enable-NetAdapter -Confirm:$false
    for($i=0;$i -lt 30;$i++){if((Adapter)[0].Status -eq 'Up'){break};Start-Sleep -Seconds 1}
    if((Adapter)[0].Status -eq 'Up'){
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
        Write-Output ('Physical adapter restored Up: '+$guid)
    } else {throw 'Adapter not Up; independent 30-second restoration task remains armed'}
}
