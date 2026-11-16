# Run from an independent local task, with an owned absolute wake timer.
$ErrorActionPreference='Stop'
$query=(& powercfg.exe /query SCHEME_CURRENT SUB_SLEEP RTCWAKE) -join "`n"
$values=[regex]::Matches($query,'0x([0-9a-fA-F]{8})')
if($values.Count -ne 2 -or [Convert]::ToInt32($values[0].Groups[1].Value,16) -ne 1){throw 'AC wake timers must already be enabled; refusing to change power policy'}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class RekaWake {
 [DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
 public static extern IntPtr CreateWaitableTimer(IntPtr attributes,bool manualReset,string name);
 [DllImport("kernel32.dll",SetLastError=true)]
 public static extern bool SetWaitableTimer(IntPtr timer,ref long due,int period,IntPtr routine,IntPtr argument,bool resume);
 [DllImport("kernel32.dll")] public static extern bool CancelWaitableTimer(IntPtr timer);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 [DllImport("powrprof.dll",SetLastError=true)]
 [return: MarshalAs(UnmanagedType.U1)]
 public static extern bool SetSuspendState([MarshalAs(UnmanagedType.U1)] bool hibernate,[MarshalAs(UnmanagedType.U1)] bool force,[MarshalAs(UnmanagedType.U1)] bool disableWake);
}
'@
$timer=[RekaWake]::CreateWaitableTimer([IntPtr]::Zero,$true,$null)
if($timer -eq [IntPtr]::Zero){throw 'Cannot create wake timer'}
try {
    [long]$due=[DateTime]::UtcNow.AddSeconds(45).ToFileTimeUtc()
    $armed=[RekaWake]::SetWaitableTimer($timer,[ref]$due,0,[IntPtr]::Zero,[IntPtr]::Zero,$true)
    $errorCode=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if(!$armed -or $errorCode -eq 50){throw 'Hardware resume timer unavailable; sleep not attempted'}
    $start=Get-Date
    if(![RekaWake]::SetSuspendState($false,$false,$false)){throw 'Native suspend request failed'}
    Start-Sleep -Seconds 5
    $events=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';StartTime=$start;Id=42,107} -ErrorAction SilentlyContinue)
    $sleep=@($events|Where-Object Id -eq 42).Count
    $resume=@($events|Where-Object Id -eq 107).Count
    if($sleep -lt 1 -or $resume -lt 1){throw 'Actual system suspend/resume events were not observed'}
    [pscustomobject]@{wall_seconds=((Get-Date)-$start).TotalSeconds;suspend_events=$sleep;resume_events=$resume;power_policy_changed=$false}|ConvertTo-Json -Compress
} finally {
    [RekaWake]::CancelWaitableTimer($timer)|Out-Null
    [RekaWake]::CloseHandle($timer)|Out-Null
}
