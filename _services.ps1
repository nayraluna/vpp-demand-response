# Dot-sourced by run_all.ps1, start_services.ps1 and watch_tunnels.ps1.
# Single source for the port list, the certificate paths and the venv lookup,
# so a change to any of them cannot land in one script and miss another.

$Ports = 8080, 8081, 8082, 8443

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
    @(
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\ca" -ArgumentList ($uvicorn + @("8081", "--ssl-keyfile", "../certs/server.key", "--ssl-certfile", "../certs/server.crt"))
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server"   -ArgumentList ($uvicorn + @("8080", "--ssl-keyfile", "../certs/vpp.key", "--ssl-certfile", "../certs/vpp.crt"))
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\vpp-server"   -ArgumentList @("mtls_server.py")
        Start-Process $py -PassThru -WindowStyle Hidden -WorkingDirectory "$root\appliance"    -ArgumentList ($uvicorn + @("8082"))
    )
}
