# start_services.ps1 - start the 4 TFG services and LEAVE THEM RUNNING.
#
# Complements run_all.ps1 (which starts them, runs the gates, and stops them).
# Use this one for interactive testing: Android app (emulator or physical
# phone via `adb reverse` / gradlew adbReverseVpp), curl, demos.
#
# Everything listens on 0.0.0.0 so both the emulator (10.0.2.2) and physical
# devices can reach it. Idempotent: kills whatever already holds the ports.
#
# Usage:  powershell -ExecutionPolicy Bypass -File .\start_services.ps1
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

$py = $null
foreach ($cand in @("$root\.venv\Scripts\python.exe", "$root\..\.venv\Scripts\python.exe")) {
    if (Test-Path $cand) { $py = (Resolve-Path $cand).Path; break }
}
if (-not $py) { $py = "python" }

# free the ports first (idempotent restart)
foreach ($p in 8080, 8081, 8082, 8443) {
    Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction Stop } catch {} }
}
Start-Sleep -Milliseconds 800

$procs = @()
$procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\manufacturer" -ArgumentList @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8081","--ssl-keyfile","../certs/server.key","--ssl-certfile","../certs/server.crt")
$procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server" -ArgumentList @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--ssl-keyfile","../certs/vpp.key","--ssl-certfile","../certs/vpp.crt")
$procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server" -ArgumentList @("mtls_server.py")
$procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\appliance" -ArgumentList @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8082")

Start-Sleep -Seconds 5

# Keep the adb reverse tunnels alive automatically: the watcher re-creates
# them whenever the phone is (re)plugged. Single instance, hidden window.
$watcher = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "-File.*watch_tunnels" -and $_.ProcessId -ne $PID }
if (-not $watcher) {
    Start-Process powershell -WindowStyle Hidden -ArgumentList @(
        "-ExecutionPolicy", "Bypass", "-File", "$root\watch_tunnels.ps1")
    Write-Host "adb tunnel watcher started (watch_tunnels.ps1)" -ForegroundColor Green
}

Write-Host "Services running (PIDs: $(($procs | ForEach-Object { $_.Id }) -join ', ')):" -ForegroundColor Green
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalPort -in 8080, 8081, 8082, 8443 } |
    Select-Object LocalAddress, LocalPort | Sort-Object LocalPort | Format-Table -AutoSize
Write-Host "Stop them with:  Get-NetTCPConnection -State Listen | ? { `$_.LocalPort -in 8080,8081,8082,8443 } | % { Stop-Process -Id `$_.OwningProcess -Force }"
