# Run only on an explicitly authorized Windows test host, as the proxy owner.
param([Parameter(Mandatory=$true)][string]$Root)
$ErrorActionPreference='Stop'
$Root=[IO.Path]::GetFullPath($Root)
$work=Join-Path $Root ('proxy-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $work | Out-Null
$reka=Join-Path $Root 'reka.exe'
$ctl=Join-Path $Root 'rekactl.exe'
$pipe='pipe://reka-acceptance-'+[guid]::NewGuid().ToString('N')
function Snapshot {
    $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Internet Settings')
    try {
        @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect') | ForEach-Object {
            $present=$key.GetValueNames() -contains $_
            [pscustomobject]@{name=$_;present=$present;value=$(if($present){$key.GetValue($_)}else{$null});kind=$(if($present){$key.GetValueKind($_).ToString()}else{$null})}
        }
    } finally { $key.Close() }
}
function FreePort {
    $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $listener.Start();$port=$listener.LocalEndpoint.Port;$listener.Stop();$port
}
function Control([string[]]$Command) {
    $text=& $ctl -c $pipe -json @Command
    if($LASTEXITCODE -ne 0){throw ('control failed: '+($Command -join ' '))}
    $text | ConvertFrom-Json
}
function StartKernel {
    $script:kernel=Start-Process $reka -ArgumentList @('-state-root',(Join-Path $work 'state'),'-control',$pipe,'-profile',(Join-Path $work 'profile.yaml'),'-local',(Join-Path $work 'local.yaml'),'-edit-dir','-') -RedirectStandardOutput (Join-Path $work 'daemon.out') -RedirectStandardError (Join-Path $work 'daemon.err') -PassThru
    $script:kernelHandle=$kernel.Handle
    for($i=0;$i -lt 50;$i++){
        if($kernel.HasExited){throw 'daemon exited before control became ready'}
        try {
            $status=Control -Command @('status')
            if($status.start_error){throw $status.start_error}
            return $status
        } catch {Start-Sleep -Milliseconds 100}
    }
    throw 'control did not become ready'
}
function CommitLocal([string]$Name) {
    $result=Control -Command @('commit','-local',(Join-Path $work $Name),'-yes')
    if($result.state -ne 'committed'){throw ('commit failed: '+($result|ConvertTo-Json -Depth 8))}
}
$before=@(Snapshot)
$report=[ordered]@{native_client='Windows PowerShell Invoke-WebRequest default system proxy';proxy=$false;crash_recovery=$false;before=$before}
$kernel=$origin=$null
try {
    $originPort=FreePort;$proxyPort=FreePort
    $origin=Start-Job -ArgumentList $originPort -ScriptBlock {
        param($port)
        $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$port)
        $listener.Start()
        try {while($true){
            if(!$listener.Pending()){Start-Sleep -Milliseconds 50;continue}
            $client=$listener.AcceptTcpClient()
            try {
                $stream=$client.GetStream();$reader=[IO.StreamReader]::new($stream)
                do{$line=$reader.ReadLine()}while($line)
                $body='REKA_SYSTEM_PROXY_PASS'
                $response="HTTP/1.1 200 OK`r`nContent-Type: text/plain; charset=utf-8`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body"
                $bytes=[Text.Encoding]::ASCII.GetBytes($response);$stream.Write($bytes,0,$bytes.Length)
            } finally {$client.Close()}
        }} finally {$listener.Stop()}
    }
    @'
schema-version: 1
dns:
 nameserver: [223.5.5.5]
 default-nameserver: [223.5.5.5]
 use-hosts: true
 hosts: [{id: fixture.reka.test, addresses: [127.0.0.1]}]
rules: [{id: final, match: {all: true}, outbound: direct}]
'@ | Set-Content -Encoding ASCII (Join-Path $work 'profile.yaml')
    "listeners: [{id: mixed, type: mixed, listen: '127.0.0.1:$proxyPort'}]`nnetwork: {mode: system-proxy, proxy-listener: mixed}" | Set-Content -Encoding ASCII (Join-Path $work 'local.yaml')
    'network: {mode: off}' | Set-Content -Encoding ASCII (Join-Path $work 'off.yaml')
    $report.status=StartKernel
    $active=@(Snapshot);$report.active=$active
    $body=(Invoke-WebRequest -UseBasicParsing -Uri "http://fixture.reka.test:$originPort/" -TimeoutSec 15).Content
    $report.body_type=$body.GetType().FullName
    if($body -is [byte[]]){$body=[Text.Encoding]::UTF8.GetString($body)}
    if($body -ne 'REKA_SYSTEM_PROXY_PASS'){throw 'system proxy response did not reach fixture origin'}
    $report.proxy=$true
    CommitLocal 'off.yaml'
    if(($before|ConvertTo-Json -Compress) -ne (@(Snapshot)|ConvertTo-Json -Compress)){throw 'graceful proxy restoration differs'}
    CommitLocal 'local.yaml'
    Stop-Process -Id $kernel.Id -Force;$kernel.WaitForExit()
    if(($active|ConvertTo-Json -Compress) -ne (@(Snapshot)|ConvertTo-Json -Compress)){throw 'crash did not leave proxy journal residue'}
    $null=StartKernel
    CommitLocal 'off.yaml'
    if(($before|ConvertTo-Json -Compress) -ne (@(Snapshot)|ConvertTo-Json -Compress)){throw 'restart proxy recovery differs'}
    $report.crash_recovery=$true
} catch {$report.error=$_.ToString()}
finally {
    if($kernel -and !$kernel.HasExited){
        try {CommitLocal 'off.yaml'} catch {$report.cleanup_error=$_.ToString()}
        Stop-Process -Id $kernel.Id -Force;$kernel.WaitForExit()
    }
    if($origin){Stop-Job $origin;Remove-Job $origin}
    $report.after=@(Snapshot)
    $report.settings_restored=($before|ConvertTo-Json -Compress) -eq ($report.after|ConvertTo-Json -Compress)
    $report.passed=$report.proxy -and $report.crash_recovery -and $report.settings_restored
    $report | ConvertTo-Json -Depth 14 | Set-Content -Encoding UTF8 (Join-Path $Root 'proxy-runtime.json')
    Get-Content (Join-Path $Root 'proxy-runtime.json')
}
if(!$report.passed){throw 'Windows system-proxy runtime acceptance failed'}
