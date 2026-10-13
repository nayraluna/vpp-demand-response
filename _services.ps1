# Dot-sourced by run_all.ps1, start_services.ps1 and watch_tunnels.ps1.
# Single source for the port list, the certificate paths and the venv lookup,
# so a change to any of them cannot land in one script and miss another.

$Ports = 8080, 8081, 8082, 8083, 8443

function Find-Python($root) {
    $venv = "$root\.venv\Scripts\python.exe"
    if (Test-Path $venv) { return (Resolve-Path $venv).Path }
    return "python"
}

function Stop-ServicePorts {
    foreach ($p in $Ports) {
        Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
            ForEach-Object { try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction Stop } catch {} }
    }
    Start-Sleep -Milliseconds 800
}

function Start-Services($py, $root) {
    $uvicorn = @("-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port")
    $tls13 = @("../serve_tls.py", "app.main:app")   # same app, TLS 1.3 only
    @(
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\ca" -ArgumentList ($tls13 + @("8081", "../certs/server.crt", "../certs/server.key"))
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server"   -ArgumentList ($tls13 + @("8080", "../certs/vpp.crt", "../certs/vpp.key"))
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server"   -ArgumentList @("mtls_server.py")
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\appliance"    -ArgumentList ($uvicorn + @("8082"))
    )
}
