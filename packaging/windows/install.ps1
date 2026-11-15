#Requires -RunAsAdministrator
param(
 [string]$OwnerSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
 [string]$BinDir = (Join-Path $env:ProgramFiles 'Reka'),
 [string]$StateRoot = (Join-Path $env:ProgramData 'Reka')
)
$ErrorActionPreference = 'Stop'
$null = [Security.Principal.SecurityIdentifier]::new($OwnerSID)
if (Get-Service Reka -ErrorAction SilentlyContinue) { throw 'Reka service already installed; uninstall before upgrading.' }
$source = Resolve-Path (Join-Path $PSScriptRoot '..\..')
if (!(Test-Path (Join-Path $source 'reka.exe'))) { $source = Join-Path $source 'bin' }
$bin = $BinDir
$state = $StateRoot
foreach ($dir in @($bin,$state)) {
    New-Item -ItemType Directory -Force $dir | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    if ($dir -eq $bin) {
        $readers=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($readers)
    }
    Set-Acl $dir $acl
}
Copy-Item (Join-Path $source 'reka.exe') (Join-Path $bin 'reka.exe')
$command = '"{0}\reka.exe" -state-root "{1}" -control pipe://reka-service -owner {2} -edit-dir -' -f $bin,$state,$OwnerSID
New-Service -Name Reka -DisplayName 'Reka proxy core' -BinaryPathName $command -StartupType Automatic | Out-Null
& sc.exe failure Reka reset= 86400 actions= restart/5000/restart/10000/restart/30000
if ($LASTEXITCODE -ne 0) { throw 'Could not configure service recovery.' }
Start-Service Reka
Write-Output 'Installed. Control: pipe://reka-service. Network mode defaults to off.'
