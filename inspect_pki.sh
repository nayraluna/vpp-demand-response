#!/usr/bin/env bash
# Read the PKI the way a relying party sees it. Run from Git Bash on the PC, or on the Pi.
#
#   bash inspect_pki.sh cert [file]       tbsCertificate fields, extensions, ASN.1 tree, chain and purpose
#   bash inspect_pki.sh key  [file]       private key format, and whether it matches its certificate
#   bash inspect_pki.sh csr  [file]       PKCS#10 request: subject, key, self-signature, ASN.1 tree
#   bash inspect_pki.sh crl               the CA's CRL, and every certificate checked against it   (services up)
#   bash inspect_pki.sh tls               each listener: version, signature, ephemeral key, mTLS    (services up)
#   bash inspect_pki.sh register [serial] the CA register, or one issued certificate pulled out of it
#   bash inspect_pki.sh jws               a stored calendar: header, payload, the certificate in x5c
#   bash inspect_pki.sh all               all of the above for the shipped identities
#
# Services: powershell -ExecutionPolicy Bypass -File .\start_services.ps1
set -u
unset OPENSSL_CONF   # a stale value makes "openssl req" and "openssl crl" fail before reading anything
cd "$(dirname "$0")"

PY=.venv/Scripts/python.exe; [ -x "$PY" ] || PY=.venv/bin/python; [ -x "$PY" ] || PY=python
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
native() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else echo "$1"; fi; }
if [ -t 1 ]; then B=$'\033[1;36m' D=$'\033[2m' R=$'\033[0m'; else B= D= R=; fi
title() { printf '\n%s== %s ==%s\n' "$B" "$*" "$R"; }
note() { printf '%s%s%s\n' "$D" "$*" "$R"; }
verdict() { grep -m1 -E ': OK$|^error [0-9]+'; }
services_up() {
    curl -s -o /dev/null --max-time 3 http://127.0.0.1:8083/ra/crl && return 0
    echo "services are not running: powershell -ExecutionPolicy Bypass -File .\\start_services.ps1"
    return 1
}
OPERATOR=backoffice/operator; [ -f $OPERATOR.crt ] || OPERATOR=certs/VEN   # any client certificate will do

cert() {
    local c=${1:-certs/VEN.crt}
    title "$c: tbsCertificate"
    note "version, serial, signature algorithm, issuer, validity, subject, public key"
    openssl x509 -in "$c" -noout -text -certopt no_extensions,no_sigdump
    title "$c: names in RFC 2253 order (most specific first), serial, dates"
    openssl x509 -in "$c" -noout -subject -issuer -serial -dates -nameopt RFC2253
    title "$c: extensions"
    note "root: CA:TRUE pathlen:0, keyCertSign cRLSign, no AKI.  leaf: CA:FALSE, digitalSignature, one EKU, AKI = root SKI, CDP"
    openssl x509 -in "$c" -noout -ext basicConstraints,keyUsage,extendedKeyUsage,subjectKeyIdentifier,authorityKeyIdentifier,subjectAltName,crlDistributionPoints,certificatePolicies
    title "$c: SHA-256 fingerprint (hash of the whole DER, what pinning compares)"
    openssl x509 -in "$c" -noout -fingerprint -sha256
    title "$c: ASN.1 tree"
    note "SEQUENCE { tbsCertificate { [0] version, serial, sigAlg, issuer, validity, subject, SPKI, [3] extensions }, sigAlg, BIT STRING }"
    openssl asn1parse -in "$c" -i
    title "$c: chain to the root, and which TLS role its EKU allows"
    openssl verify -CAfile certs/CA.crt "$c" 2>&1 | verdict
    printf 'as a TLS client: '; openssl verify -CAfile certs/CA.crt -purpose sslclient "$c" 2>&1 | verdict
    printf 'as a TLS server: '; openssl verify -CAfile certs/CA.crt -purpose sslserver "$c" 2>&1 | verdict
}

key() {
    local k=${1:-certs/VEN.key}
    title "$k: format and public half (the private value is never printed)"
    note "BEGIN PRIVATE KEY = PKCS#8; prime256v1 = P-256"
    head -1 "$k"
    openssl pkey -in "$k" -noout -text_pub
    title "$k: does it belong to ${k%.key}.crt?"
    if cmp -s <(openssl x509 -in "${k%.key}.crt" -noout -pubkey) <(openssl pkey -in "$k" -pubout); then
        echo "yes, same public key"
    else
        echo "NO, the certificate certifies another key"
    fi
}

csr() {
    local r=${1:-certs/VEN.csr}
    title "$r: what the requester asks for"
    note "subject, public key, empty attributes; the self-signature is the proof of possession"
    openssl req -in "$r" -noout -text -verify
    title "$r: ASN.1 tree"
    note "SEQUENCE { CertificationRequestInfo { version 0, subject, SPKI, [0] attributes }, sigAlg, BIT STRING }"
    openssl asn1parse -in "$r" -i
}

crl() {
    services_up || return
    curl -sS http://127.0.0.1:8083/ra/crl -o "$TMP/crl.der"
    title "CRL from http://127.0.0.1:8083/ra/crl (plain HTTP: it is checked by its signature)"
    note "v2, issuer, thisUpdate, nextUpdate (+24 h), CRL Number, AKI, one entry per revoked serial with its reason"
    openssl crl -in "$TMP/crl.der" -inform DER -noout -text -CAfile certs/CA.crt
    title "CRL: ASN.1 tree"
    note "SEQUENCE { tbsCertList { version 1, sigAlg, issuer, thisUpdate, nextUpdate, entries, [0] extensions }, sigAlg, BIT STRING }"
    openssl asn1parse -in "$TMP/crl.der" -inform DER -i
    title "every shipped certificate checked against the CRL"
    openssl crl -in "$TMP/crl.der" -inform DER -out "$TMP/crl.pem"
    cat certs/CA.crt "$TMP/crl.pem" > "$TMP/ca_crl.pem"
    for c in certs/server.crt certs/vpp.crt certs/VEN.crt $OPERATOR.crt; do
        openssl verify -crl_check -CAfile "$TMP/ca_crl.pem" "$c" 2>&1 | verdict
    done
    if "$PY" - "$(native "$TMP/revoked.crt")" <<'EOF'
import sqlite3, sys
row = sqlite3.connect("ca/ca.db").execute(
    "SELECT certificate FROM issued WHERE revoked_at IS NOT NULL AND certificate IS NOT NULL LIMIT 1").fetchone()
if not row:
    sys.exit(1)
open(sys.argv[1], "w").write(row[0])
EOF
    then
        title "a revoked certificate from the register, against the same CRL"
        openssl x509 -in "$TMP/revoked.crt" -noout -subject -serial
        openssl verify -crl_check -CAfile "$TMP/ca_crl.pem" "$TMP/revoked.crt" 2>&1 | verdict
    fi
}

tls() {
    services_up || return
    for port in 8081 8080; do
        title "TLS on :$port"
        note "TLSv1.3, ecdsa_secp256r1_sha256 = the certificate signs the handshake, Peer Temp Key X25519 = ephemeral ECDHE"
        openssl s_client -connect 127.0.0.1:$port -CAfile certs/CA.crt -brief </dev/null 2>&1 | grep -v "SSL_get_servername"
    done
    title "chain the VPP sends on :8080 (s: subject, i: issuer)"
    openssl s_client -connect 127.0.0.1:8080 -CAfile certs/CA.crt -showcerts </dev/null 2>/dev/null | grep -E '^ *[0-9]+ s:|^ +i:'
    title "mutual TLS on :8443 with $OPERATOR.crt"
    openssl s_client -connect 127.0.0.1:8443 -cert $OPERATOR.crt -key $OPERATOR.key -CAfile certs/CA.crt -brief </dev/null 2>&1 | grep -v "SSL_get_servername"
    note "a request over that channel reaches the application:"
    printf 'GET /session HTTP/1.0\r\n\r\n' | openssl s_client -connect 127.0.0.1:8443 -cert $OPERATOR.crt -key $OPERATOR.key -CAfile certs/CA.crt -quiet 2>/dev/null | tail -1; echo
    title "mutual TLS on :8443 without a client certificate"
    printf 'GET /session HTTP/1.0\r\n\r\n' | openssl s_client -connect 127.0.0.1:8443 -CAfile certs/CA.crt -quiet 2>&1 | grep -E "errno|alert|error" | head -2
    note "the server aborts once it sees no certificate (errno 10054 on Windows)"
    title "a client limited to TLS 1.2 (TLS 1.3 only is pending); with EC keys it can only be ECDHE-ECDSA"
    for port in 8080 8081 8443; do
        printf ':%s  ' $port
        openssl s_client -connect 127.0.0.1:$port -CAfile certs/CA.crt -tls1_2 -cert $OPERATOR.crt -key $OPERATOR.key </dev/null 2>/dev/null \
            | awk '/^ +Protocol +:/ { p = $3 } /^ +Cipher +:/ { c = $3 } END { print (p ? p "  " c : "refused") }'
    done
}

register() {
    if [ -n "${1:-}" ]; then
        local s; s=$(echo "$1" | tr -d ': ' | tr 'A-F' 'a-f' | sed 's/^0*//')
        title "certificate $s as the CA issued it"
        "$PY" - "$s" > "$TMP/issued.crt" <<'EOF' || { echo "serial not in the register"; return; }
import sqlite3, sys
row = sqlite3.connect("ca/ca.db").execute("SELECT certificate FROM issued WHERE serial=?", (sys.argv[1],)).fetchone()
if not row or not row[0]:
    sys.exit(1)
print(row[0], end="")
EOF
        openssl x509 -in "$TMP/issued.crt" -noout -text -certopt no_sigdump,no_pubkey
        return
    fi
    title "CA register: the last 15 certificates issued"
    note "serial | subject | profile | not_after | revoked_at | reason | revoked_by"
    "$PY" - <<'EOF'
import sqlite3
c = sqlite3.connect("ca/ca.db")
for r in c.execute("SELECT serial, subject, profile, substr(not_after,1,10), substr(revoked_at,1,19),"
                   " reason, revoked_by FROM issued ORDER BY issued_at DESC LIMIT 15"):
    print(" | ".join("-" if v is None else str(v) for v in r))
print("CRL number:", c.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()[0])
EOF
    note "one of them in full: bash inspect_pki.sh register <serial>"
}

jws() {
    title "a stored availability calendar (read only, the services verify it against the root)"
    "$PY" - "$(native "$TMP/x5c.der")" <<'EOF' || return
import base64, json, sqlite3, sys
import jwt
row = sqlite3.connect("vpp-server/vpp.db").execute("SELECT jws FROM availability LIMIT 1").fetchone()
if not row:
    print("no calendar stored yet: run the suite or declare one from the app")
    sys.exit(1)
token = row[0]
header = jwt.get_unverified_header(token)
print("header: ", json.dumps({k: (v if k != "x5c" else ["<certificate>"]) for k, v in header.items()}))
payload = jwt.decode(token, options={"verify_signature": False})
print("payload:", json.dumps({**payload, "slots": {d: s[:12] + "..." for d, s in payload["slots"].items()}}))
print("parts:  ", " . ".join(f"{len(p)} chars" for p in token.split(".")), "(header . payload . signature, base64url)")
open(sys.argv[1], "wb").write(base64.b64decode(header["x5c"][0]))
EOF
    title "the certificate inside x5c"
    openssl x509 -in "$TMP/x5c.der" -inform DER -out "$TMP/x5c.pem"
    openssl x509 -in "$TMP/x5c.pem" -noout -subject -issuer -serial -nameopt RFC2253
    openssl verify -CAfile certs/CA.crt "$TMP/x5c.pem" 2>&1 | verdict
}

case "${1:-}" in
    cert|key|csr|crl|tls|register|jws) "$@" ;;
    all)
        for c in certs/CA.crt certs/server.crt certs/vpp.crt certs/VEN.crt $OPERATOR.crt; do cert "$c"; done
        key certs/VEN.key; csr certs/VEN.csr; csr certs/vpp.csr
        crl; tls; register; jws ;;
    *) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" ;;
esac
