# watch_tunnels.ps1 - keeps the adb reverse tunnels alive, automatically.
#
# The tunnels (phone's 127.0.0.1:{8080,8081,8082,8443} -> this PC) die every
# time the USB cable is unplugged or the phone reboots. This watcher polls the
# adb connection and re-creates them whenever the device (re)appears, so
# plugging the cable is all it takes.
#
# start_services.ps1 launches it automatically (hidden, single instance).
# Standalone use:  powershell -ExecutionPolicy Bypass -File .\watch_tunnels.ps1
#
# Stop it with:    Get-CimInstance Win32_Process |
#                    ? { $_.CommandLine -match "watch_tunnels" } |
#                    % { Stop-Process -Id $_.ProcessId -Force }

$ports = 8080, 8081, 8082, 8443

$adb = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"
if (-not (Test-Path $adb)) { $adb = "adb" }  # fall back to PATH

Write-Host "watching adb for ports: $($ports -join ', ') (Ctrl+C to stop)"
while ($true) {
    try {
        $state = & $adb get-state 2>$null
        if ($state -eq "device") {
            $list = (& $adb reverse --list 2>$null) -join "`n"
            $missing = @($ports | Where-Object { $list -notmatch "tcp:$($_)\b" })
            if ($missing.Count -gt 0) {
                foreach ($p in $ports) { & $adb reverse "tcp:$p" "tcp:$p" | Out-Null }
                Write-Host "$(Get-Date -Format HH:mm:ss) device connected -> tunnels recreated"
            }
        }
    } catch { }
    Start-Sleep -Seconds 3
}
