#!/usr/bin/env bash
# The PKI read with standard OpenSSL commands, each printed before its output.
#
#   bash inspect_pki.sh cert <name>    a certificate and its chain: CA, server, vpp, VEN, operator
#   bash inspect_pki.sh csr <name>     a certificate request: vpp, VEN
#   bash inspect_pki.sh crl            the CRL, a valid and a revoked certificate against it
#   bash inspect_pki.sh mtls           mutual TLS with and without a client certificate
#   bash inspect_pki.sh                all of it, with the root and the VPP certificate
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
# A name (CA, vpp, VEN...) or a path, for a given extension. Errors out listing what exists.
find_file() {
    local name=$1 ext=$2 f
    for f in "$name" "certs/$name" "certs/$name.$ext" "backoffice/$name.$ext"; do
        [ -n "$name" ] && [ -f "$f" ] && { echo "$f"; return; }
    done
    local have; have=$(ls certs/*.$ext backoffice/*.$ext 2>/dev/null | xargs -n1 basename | sed "s/\.$ext$//" | tr '\n' ' ')
    if [ -n "$name" ]; then echo "no .$ext called '$name'. Available: $have" >&2
    else echo "which one? Available: $have" >&2; fi
    return 1
}

cert() {
    local c; c=$(find_file "${1:-}" crt) || return 1
    run "openssl x509 -in $c -noout -text"
    run "openssl verify -CAfile certs/CA.crt $c"
}

csr() {
    local r; r=$(find_file "${1:-}" csr) || return 1
    run "openssl req -in $r -noout -text -verify"
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

case "${1:-}" in
    cert|csr|crl|mtls) "$@" ;;
    "") cert CA; cert vpp; csr VEN; crl; mtls ;;
    *) echo "unknown section '$1': cert, csr, crl or mtls"; exit 1 ;;
esac
