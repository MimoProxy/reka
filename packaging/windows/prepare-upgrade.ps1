# Stop only the Reka service installed in the selected directory, before files
# are replaced by Setup. Keep its owner and state path for install.ps1 -Upgrade.
#Requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$BinDir,[string]$OwnerSID='')
$ErrorActionPreference='Stop'
if($OwnerSID){$null=[Security.Principal.SecurityIdentifier]::new($OwnerSID)}
$existing=Get-Service Reka -ErrorAction SilentlyContinue
if (!$existing) { exit 0 }
$path=(Get-CimInstance Win32_Service -Filter "Name='Reka'").PathName
if ($path -notmatch '^"([^"]+)" -state-root "([^"]+)" -control pipe://reka-service -owner (S-[0-9-]+) -edit-dir -$') { throw 'Unrecognized Reka service; refusing to stop it.' }
if($OwnerSID -and $OwnerSID -ne $Matches[3]){throw 'Upgrade cannot change the existing control owner'}
if ([IO.Path]::GetFullPath($Matches[1]) -ine [IO.Path]::GetFullPath((Join-Path $BinDir 'reka.exe'))) { throw 'Reka is installed in another directory.' }
if ($existing.Status -ne 'Stopped') { Stop-Service Reka; $existing.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
