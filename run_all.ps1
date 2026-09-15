$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
. "$root\_services.ps1"

# Hourly, so no background tick races the polls the gates drive themselves.
$env:TFG_POLL_SECONDS = "3600"

# Loopback: the deployed Pi shares this VEN identity and would steal the gates'
# activations. start_services.ps1 keeps 0.0.0.0 for interactive use.
$env:TFG_MTLS_HOST = "127.0.0.1"

# A leftover start_services.ps1 would answer the check below, wrongly configured.
Stop-ServicePorts

$py = Find-Python $root
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

try {
    Write-Host "Starting services..." -ForegroundColor Cyan
    $procs = Start-Services $py $root

    foreach ($pt in $Ports) {
        if (-not (Wait-Port $pt)) { throw "service on port $pt did not start (port already in use?)" }
    }
    Write-Host "All services up ($($Ports -join ', ')).`n" -ForegroundColor Green

    $gates = "verify_setup","verify_jws","verify_ca","verify_enroll","verify_mtls",
             "verify_pair","verify_owner_proof","verify_openadr","verify_availability",
             "verify_selection","verify_activation","verify_evidence",
             "verify_remuneration","verify_backoffice"
    $fail = 0
    foreach ($g in $gates) {
        # No 2>&1: PowerShell 5.1 wraps native stderr in a NativeCommandError.
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
