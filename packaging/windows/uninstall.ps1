#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$service=Get-Service Reka -ErrorAction SilentlyContinue
if ($service) {
    Stop-Service Reka
    $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    & sc.exe delete Reka
    if ($LASTEXITCODE -ne 0) { throw 'Could not delete service.' }
}
Write-Output 'Service stopped. State and binary retained for recovery or reinstallation.'
