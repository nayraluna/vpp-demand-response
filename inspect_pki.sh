#!/usr/bin/env bash
# The PKI read with standard OpenSSL commands, each printed before its output.
#
#   bash inspect_pki.sh [cert|csr|crl|mtls]     no argument runs all four
#
# crl and mtls need the services: powershell -ExecutionPolicy Bypass -File .\start_services.ps1
unset OPENSSL_CONF
cd "$(dirname "$0")"
trap 'rm -f crl.der crl.pem revoked.pem' EXIT
PY=.venv/Scripts/python.exe; [ -x "$PY" ] || PY=.venv/bin/python

run() { printf '\n$ %s\n' "$1"; eval "$1"; }
services_up() {
    curl -s -o /dev/null --max-time 3 http://127.0.0.1:8083/ra/crl && return
    echo "start the services first: powershell -ExecutionPolicy Bypass -File .\\start_services.ps1"
    return 1
}

cert() {
    run "openssl x509 -in certs/vpp.crt -noout -text"
    run "openssl verify -CAfile certs/CA.crt certs/vpp.crt"
}

csr() {
    run "openssl req -in certs/VEN.csr -noout -text -verify"
}

crl() {
    services_up || return
    run "curl -sS http://127.0.0.1:8083/ra/crl -o crl.der"
    run "openssl crl -in crl.der -inform DER -noout -text -CAfile certs/CA.crt"
    run "openssl crl -in crl.der -inform DER -out crl.pem"
    run "openssl verify -crl_check -CAfile certs/CA.crt -CRLfile crl.pem certs/VEN.crt"
    # revoked.pem: a certificate the CA revoked, taken from its register.
    "$PY" -c "import sqlite3; print(sqlite3.connect('ca/ca.db').execute(\"SELECT certificate FROM issued WHERE reason = 'keyCompromise' ORDER BY revoked_at DESC\").fetchone()[0], end='')" \
        > revoked.pem 2>/dev/null || { echo "no revoked certificate yet: run run_all.ps1 first"; return; }
    run "openssl verify -crl_check -CAfile certs/CA.crt -CRLfile crl.pem revoked.pem"
}

mtls() {
    services_up || return
    [ -f backoffice/operator.crt ] || "$PY" backoffice/dr_operator.py init
    run "openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -cert backoffice/operator.crt -key backoffice/operator.key -brief -noservername </dev/null"
    run "echo | openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -brief -noservername"
}

if [ -n "${1:-}" ]; then "$1"; else cert; csr; crl; mtls; fi
