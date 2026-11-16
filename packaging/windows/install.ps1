#Requires -RunAsAdministrator
param(
 [string]$OwnerSID = '',
 [string]$BinDir = (Join-Path $env:ProgramFiles 'Reka'),
 [string]$StateRoot = (Join-Path $env:ProgramData 'Reka'),
 [switch]$Upgrade
)
$ErrorActionPreference = 'Stop'
$existing = Get-Service Reka -ErrorAction SilentlyContinue
if ($existing) {
    if (!$Upgrade) { throw 'Reka service already installed; use -Upgrade for an in-place update.' }
    $serviceInfo = Get-CimInstance Win32_Service -Filter "Name='Reka'"
    $path = $serviceInfo.PathName
    if ($path -notmatch '^"([^"]+)" -state-root "([^"]+)" -control pipe://reka-service -owner (S-[0-9-]+) -edit-dir -$') { throw 'Unrecognized service command; refusing to replace it.' }
    $oldBin=$Matches[1];$oldState=$Matches[2];$oldOwner=$Matches[3]
    if ([IO.Path]::GetFullPath($oldBin) -ine [IO.Path]::GetFullPath((Join-Path $BinDir 'reka.exe'))) { throw 'Service belongs to another directory; refusing to migrate it.' }
    if ($OwnerSID -and $OwnerSID -ne $oldOwner) { throw 'Upgrade cannot change the service control owner.' }
    $OwnerSID=$oldOwner;$StateRoot=$oldState
    if ($existing.Status -ne 'Stopped') { Stop-Service Reka; $existing.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
}
if (!$OwnerSID) { $OwnerSID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
$null = [Security.Principal.SecurityIdentifier]::new($OwnerSID)
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
$inputBinary=[IO.Path]::GetFullPath((Join-Path $source 'reka.exe'))
$outputBinary=[IO.Path]::GetFullPath((Join-Path $bin 'reka.exe'))
if ($inputBinary -ine $outputBinary) { Copy-Item $inputBinary $outputBinary -Force }
$command = '"{0}\reka.exe" -state-root "{1}" -control pipe://reka-service -owner {2} -edit-dir -' -f $bin,$state,$OwnerSID
if ($existing) {
    # The validated command already names this binary and the preserved owner
    # and state. Keep it verbatim; avoid native command-line quote rewriting.
    Set-Service Reka -StartupType Automatic
} else {
    New-Service -Name Reka -DisplayName 'Reka proxy core' -BinaryPathName $command -StartupType Automatic | Out-Null
}
& sc.exe failure Reka reset= 86400 actions= restart/5000/restart/10000/restart/30000
if ($LASTEXITCODE -ne 0) { throw 'Could not configure service recovery.' }
Start-Service Reka
Write-Output 'Installed. Control: pipe://reka-service. Network mode defaults to off.'
