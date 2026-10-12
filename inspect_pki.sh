#!/usr/bin/env bash
# The PKI as a relying party sees it, with standard OpenSSL commands.
#
#   bash inspect_pki.sh               all four sections
#   bash inspect_pki.sh cert [file]   a certificate, its issuer, the chain and the EKU
#   bash inspect_pki.sh csr [file]    a certificate request and its proof of possession
#   bash inspect_pki.sh crl           the CRL, a valid and a revoked certificate against it
#   bash inspect_pki.sh mtls          mutual TLS with and without a client certificate
#
# crl and mtls need the services: powershell -ExecutionPolicy Bypass -File .\start_services.ps1
unset OPENSSL_CONF   # a stale value makes "openssl req" and "openssl crl" fail
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
    local c=${1:-certs/vpp.crt}
    run "openssl x509 -in $c -noout -text"
    run "openssl x509 -in certs/CA.crt -noout -ext basicConstraints,keyUsage,subjectKeyIdentifier"
    run "openssl verify -CAfile certs/CA.crt $c"
    run "openssl verify -CAfile certs/CA.crt -purpose sslclient $c"
}

csr() {
    run "openssl req -in ${1:-certs/VEN.csr} -noout -text -verify"
}

crl() {
    services_up || return
    run "curl -sS http://127.0.0.1:8083/ra/crl -o crl.der"
    run "openssl crl -in crl.der -inform DER -noout -text -CAfile certs/CA.crt"
    run "openssl crl -in crl.der -inform DER -out crl.pem"
    run "openssl verify -crl_check -CAfile certs/CA.crt -CRLfile crl.pem certs/VEN.crt"
    # A certificate the CA did revoke, taken from its register.
    "$PY" - > revoked.pem <<'EOF' || { printf '\nno revoked certificate yet: run run_all.ps1 first\n'; return; }
import sqlite3, sys
row = sqlite3.connect("ca/ca.db").execute(
    "SELECT certificate FROM issued WHERE revoked_at IS NOT NULL AND certificate IS NOT NULL"
    " ORDER BY reason = 'keyCompromise' DESC, revoked_at DESC LIMIT 1").fetchone()
sys.exit(1) if not row else print(row[0], end="")
EOF
    run "openssl x509 -in revoked.pem -noout -subject -serial"
    run "openssl verify -crl_check -CAfile certs/CA.crt -CRLfile crl.pem revoked.pem"
}

mtls() {
    services_up || return
    [ -f backoffice/operator.crt ] || run "$PY backoffice/dr_operator.py init"
    run "openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -cert backoffice/operator.crt -key backoffice/operator.key -brief -noservername </dev/null"
    # TLS 1.3 authenticates the client after the server's Finished, so the client sees
    # CONNECTION ESTABLISHED and then the refusal: alert 116 certificate_required, or the close.
    run "echo | openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -brief -noservername"
}

case "${1:-}" in
    cert|csr|crl|mtls) "$@" ;;
    "") cert; csr; crl; mtls ;;
    *) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" ;;
esac
