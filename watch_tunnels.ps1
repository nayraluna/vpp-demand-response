# The adb reverse tunnels die whenever the cable is unplugged or the phone
# reboots, so this polls and recreates them. start_services.ps1 runs it hidden,
# so stop it with:
#   Get-CimInstance Win32_Process | ? { $_.CommandLine -match "watch_tunnels" } |
#     % { Stop-Process -Id $_.ProcessId -Force }

. "$PSScriptRoot\_services.ps1"

$adb = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"
if (-not (Test-Path $adb)) { $adb = "adb" }

Write-Host "watching adb for ports: $($Ports -join ', ') (Ctrl+C to stop)"
while ($true) {
    try {
        $state = & $adb get-state 2>$null
        if ($state -eq "device") {
            $list = (& $adb reverse --list 2>$null) -join "`n"
            if ($Ports | Where-Object { $list -notmatch "tcp:$($_)" }) {
                foreach ($p in $Ports) { & $adb reverse "tcp:$p" "tcp:$p" | Out-Null }
                Write-Host "$(Get-Date -Format HH:mm:ss) device connected -> tunnels recreated"
            }
        }
    } catch { }
    Start-Sleep -Seconds 3
}
