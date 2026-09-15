$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
. "$root\_services.ps1"

$py = Find-Python $root

# Freed first, so re-running this restarts cleanly.
Stop-ServicePorts

# 0.0.0.0, not loopback: the emulator (10.0.2.2) and physical devices both have
# to reach these. run_all.ps1 pins loopback instead.
$procs = Start-Services $py $root

Start-Sleep -Seconds 5

# Single instance: the watcher outlives this script, so do not stack copies.
$watcher = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "-File.*watch_tunnels" -and $_.ProcessId -ne $PID }
if (-not $watcher) {
    Start-Process powershell -WindowStyle Hidden -ArgumentList @(
        "-ExecutionPolicy", "Bypass", "-File", "$root\watch_tunnels.ps1")
    Write-Host "adb tunnel watcher started (watch_tunnels.ps1)" -ForegroundColor Green
}

Write-Host "Services running (PIDs: $(($procs | ForEach-Object { $_.Id }) -join ', ')):" -ForegroundColor Green
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in $Ports } |
    Select-Object LocalAddress, LocalPort | Sort-Object LocalPort | Format-Table -AutoSize
Write-Host "Stop them with:  Get-NetTCPConnection -State Listen | ? { `$_.LocalPort -in 8080,8081,8082,8443 } | % { Stop-Process -Id `$_.OwningProcess -Force }"
