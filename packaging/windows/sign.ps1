param([Parameter(Mandatory=$true)][string]$File,[Parameter(Mandatory=$true)][string]$Thumbprint,[string]$TimestampURL='http://timestamp.digicert.com')
$ErrorActionPreference='Stop'
& signtool.exe sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampURL /td SHA256 $File
if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed.' }
& signtool.exe verify /pa /all $File
if ($LASTEXITCODE -ne 0) { throw 'Authenticode verification failed.' }

$directory=Split-Path -Parent (Resolve-Path $File)
$metadataFile=Join-Path $directory 'BUILD.json'
$name=Split-Path -Leaf $File
if(($name -in @('reka.exe','rekactl.exe')) -and (Test-Path $metadataFile)) {
    $metadata=Get-Content $metadataFile | ConvertFrom-Json
    $metadata.binaries.$name.bytes=(Get-Item $File).Length
    $metadata.binaries.$name.sha256=(Get-FileHash -Algorithm SHA256 $File).Hash.ToLowerInvariant()
    $metadata.signed=(@('reka.exe','rekactl.exe') | Where-Object { (Get-AuthenticodeSignature (Join-Path $directory $_)).Status -ne 'Valid' }).Count -eq 0
    $metadata | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $metadataFile
}
