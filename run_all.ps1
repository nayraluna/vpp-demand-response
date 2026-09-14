# run_all.ps1 - start every TFG service, run all verification gates, then stop.
#
# Usage (from the repo root):
#   powershell -ExecutionPolicy Bypass -File .\run_all.ps1
#
# Starts: Manufacturer/RA (:8081), VPP normal-TLS (:8080), VPP mutual-TLS (:8443),
# appliance pairing (:8082). Runs every gate. Stops the services on exit.
#
# The appliance's periodic VTN polling stays out of the way (one tick per hour):
# the gates drive each poll cycle explicitly through /poll and /evidence, so
# their positive/negative checks are deterministic regardless of wall clock.
#
# The mutual-TLS endpoint binds to LOOPBACK during the run: the deployed
# Raspberry Pi holds the same VEN identity and polls every minute, and a tick
# landing between a gate issuing an activation and its manual /poll would
# consume it (observed as "polled: 0" flakes). Interactive use keeps 0.0.0.0
# via start_services.ps1.
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$env:TFG_POLL_SECONDS = "3600"
$env:TFG_MTLS_HOST = "127.0.0.1"

# Free the ports first. A leftover service from an interactive session
# (start_services.ps1) would otherwise answer the port check below and the
# gates would silently run against IT, with the WRONG environment: a live
# 60-second polling loop and mTLS on 0.0.0.0. That is the root cause of the
# historical "nothing submitted" / stolen-activation flakes.
foreach ($p in 8080, 8081, 8082, 8443) {
    Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction Stop } catch {} }
}
Start-Sleep -Milliseconds 800

# --- locate the venv python -------------------------------------------------
$py = $null
foreach ($cand in @("$root\..\.venv\Scripts\python.exe", "$root\.venv\Scripts\python.exe")) {
    if (Test-Path $cand) { $py = (Resolve-Path $cand).Path; break }
}
if (-not $py) { $py = "python" }
Write-Host "Python: $py`n"

function Wait-Port([int]$port, [int]$timeoutSec = 25) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect("127.0.0.1", $port); $c.Close(); return $true
        } catch { Start-Sleep -Milliseconds 300 }
    }
    return $false
}

$procs = @()
try {
    Write-Host "Starting services..." -ForegroundColor Cyan
    $procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\manufacturer" -ArgumentList @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8081","--ssl-keyfile","../certs/server.key","--ssl-certfile","../certs/server.crt")
    $procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server" -ArgumentList @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--ssl-keyfile","../certs/vpp.key","--ssl-certfile","../certs/vpp.crt")
    $procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server" -ArgumentList @("mtls_server.py")
    $procs += Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\appliance" -ArgumentList @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8082")

    foreach ($pt in 8080,8081,8082,8443) {
        if (-not (Wait-Port $pt)) { throw "service on port $pt did not start (port already in use?)" }
    }
    Write-Host "All services up (8080, 8081, 8082, 8443).`n" -ForegroundColor Green

    $gates = "verify_setup","verify_jws","verify_ca","verify_enroll","verify_mtls",
             "verify_pair","verify_owner_proof","verify_openadr","verify_availability",
             "verify_selection","verify_activation","verify_evidence",
             "verify_remuneration","verify_backoffice"
    $fail = 0
    foreach ($g in $gates) {
        # No 2>&1 here: in PowerShell 5.1 redirecting a native command's stderr
        # wraps each line in a NativeCommandError, which hides the real failure.
        $out = & $py "$root\tests\$g.py"
        $code = $LASTEXITCODE
        $last = ($out | Select-Object -Last 1)
        if ($code -eq 0) {
            Write-Host ("  [OK]   {0,-16} {1}" -f $g, $last) -ForegroundColor Green
        } else {
            Write-Host ("  [FAIL] {0}" -f $g) -ForegroundColor Red
            $out | ForEach-Object { Write-Host "         $_" }
            $fail++
        }
    }
    Write-Host ""
    if ($fail -eq 0) {
        Write-Host "ALL GATES PASSED." -ForegroundColor Green
    } else {
        Write-Host "$fail gate(s) FAILED." -ForegroundColor Red
    }
}
finally {
    Write-Host "`nStopping services..." -ForegroundColor Cyan
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}
