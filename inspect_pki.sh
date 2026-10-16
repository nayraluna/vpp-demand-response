#!/usr/bin/env bash

# Usage: bash inspect_pki.sh [cert|csr|crl|mtls]
# CRL and mTLS checks require running services.

unset OPENSSL_CONF
cd "$(dirname "$0")" || exit 1

trap 'rm -f crl.der crl.pem revoked.pem' EXIT

PY=.venv/Scripts/python.exe
[ -x "$PY" ] || PY=.venv/bin/python

run() {
    eval "$1"
}

services_up() {
    curl -s -o /dev/null --max-time 3 http://127.0.0.1:8083/ra/crl/platform && return 0
    echo "Start the services first: powershell -ExecutionPolicy Bypass -File .\\start_services.ps1" >&2
    return 1
}

cert() {
    run "openssl x509 -in certs/CA.crt -noout -text"
    run "openssl x509 -in certs/VEN.crt -noout -text"
    run "openssl x509 -in certs/vpp.crt -noout -text"
    run "openssl verify -CAfile certs/CA.crt certs/vpp.crt"
}

csr() {
    run "openssl req -in certs/VEN.csr -noout -text -verify"
}

crl() {
    services_up || return 1

    # The device CA's list covers the appliance; its chain to the root goes through that CA.
    run "curl -sS http://127.0.0.1:8083/ra/crl/device -o crl.der"
    run "openssl crl -in crl.der -inform DER -noout -text"
    run "openssl crl -in crl.der -inform DER -out crl.pem"
    run "openssl verify -crl_check -CAfile certs/CA.crt -untrusted certs/device-ca.crt -CRLfile crl.pem certs/VEN.crt"
    # The platform CA's list covers users, the operator and the VPP.
    run "curl -sS http://127.0.0.1:8083/ra/crl/platform -o crl.der"
    run "openssl crl -in crl.der -inform DER -out crl.pem"

    # Retrieve the most recently revoked certificate with reason keyCompromise.
    "$PY" -c "import sqlite3; print(sqlite3.connect('ca/platform.db').execute(\"SELECT certificate FROM issued WHERE reason = 'keyCompromise' ORDER BY revoked_at DESC\").fetchone()[0], end='')" \
        > revoked.pem 2>/dev/null || {
        echo "No revoked certificate found." >&2
        return 1
    }

    run "openssl x509 -in revoked.pem -noout -subject -serial"
    run "openssl verify -crl_check -CAfile certs/CA.crt -untrusted certs/platform-ca.crt -CRLfile crl.pem revoked.pem"
}

mtls() {
    services_up || return 1

    [ -f backoffice/operator.crt ] || { echo "no operator credential: run provision_all.py first"; return; }

    run "openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -cert backoffice/operator.crt -key backoffice/operator.key -brief -noservername </dev/null"
    run "echo | openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -brief -noservername"
}

if [ -n "${1:-}" ]; then
    "$1"
else
    cert
    csr
    crl
    mtls
fi
