#!/usr/bin/env bash
# =============================================================================
# SETUP PHASE - PKI generation
#
# The RA, hosted at the CA service, acts as the platform Certificate
# Authority (a self-signed root = the common trust anchor). It issues ONE
# identity per protocol entity, matching the paper's Setup Phase (Sec. 3.1):
#
#   CA.key / CA.crt              RA root / trust anchor (self-signed)
#   vpp.key / vpp.crt / vpp.p12  VPP identity (VTN): serves TLS on :8080 AND
#                                signs DR events                (Cert_VPP)
#   server.key / server.crt      Manufacturer identity: the internet-facing
#                                server that hosts the RA, serves TLS on :8081
#   VEN.key / VEN.crt / VEN.p12  Appliance identity (VEN): HSM signing key
#                                (Cert_VEN)
#
# ONE certificate per entity (as in the paper). The VPP certificate
# authenticates the VPP both as the endpoint of the platform's secure channels
# and as the issuer of DR events, so it carries serverAuth + a localhost SAN
# (for TLS) as well as digitalSignature (for event signing).
#
# NOTE on the VEN key: in production it is generated INSIDE the appliance HSM
# and never leaves it (EdDSA in the paper); the RA only certifies the public
# key. In the prototype the "factory" step is emulated here with openssl (RSA
# for now). The VEN cert also carries clientAuth so it can authenticate the
# appliance as an OpenADR VEN to the VTN later.
#
# Run from certs/:  bash make_certs.sh
# =============================================================================
set -e

# --- Windows / Git Bash gotchas (do NOT remove) ------------------------------
# PostgreSQL leaves a stale OPENSSL_CONF pointing at a file that does not
# exist, which makes openssl abort on startup; unset it so openssl falls back
# to its built-in defaults. MSYS_NO_PATHCONV / MSYS2_ARG_CONV_EXCL stop Git
# Bash from rewriting the -subj "/CN=..." arguments into Windows paths.
unset OPENSSL_CONF
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
# -----------------------------------------------------------------------------

# Development PKCS#12 passphrase. The bundles it protects are generated locally
# by this script and are gitignored, so this is a placeholder, not a secret.
P12_PASS="${P12_PASS:-changeit}"

# TLS SANs. localhost and 127.0.0.1 cover the whole suite; 10.0.2.2 is the
# fixed alias the Android emulator uses to reach its host. To reach the
# services from a real phone or a Raspberry Pi, add this machine's LAN address:
#
#   EXTRA_SAN_IPS="192.168.1.50,192.168.1.51" bash make_certs.sh
#
TLS_SAN="subjectAltName = DNS:localhost, IP:127.0.0.1, IP:10.0.2.2"
if [ -n "${EXTRA_SAN_IPS:-}" ]; then
  IFS=',' read -ra _extra <<< "$EXTRA_SAN_IPS"
  for _ip in "${_extra[@]}"; do
    _ip="$(echo "$_ip" | tr -d '[:space:]')"
    [ -n "$_ip" ] && TLS_SAN="$TLS_SAN, IP:$_ip"
  done
  echo "== extra SAN addresses: $EXTRA_SAN_IPS =="
fi

echo "== RA root CA (self-signed, hosted at the CA service) =="
# The explicit CA extensions matter: Python 3.13 enables strict RFC 5280
# validation by default (VERIFY_X509_STRICT), which rejects any chain whose
# root lacks the keyUsage extension ("CA cert does not include key usage
# extension"). The appliance on the Raspberry Pi runs Python 3.13, so the
# whole platform PKI must be conformant.
openssl genrsa -out CA.key 4096
openssl req -x509 -new -key CA.key -sha256 -days 730 \
  -subj "/CN=TFG-RA Root CA/O=Manufacturer/C=ES" \
  -addext "basicConstraints = critical, CA:TRUE" \
  -addext "keyUsage = critical, keyCertSign, cRLSign" \
  -out CA.crt

issue () { # issue <name> <subject> <extfile-content>
  local name=$1 subj=$2 ext=$3
  openssl genrsa -out ${name}.key 2048
  openssl req -new -key ${name}.key -subj "${subj}" -out ${name}.csr
  # SKI/AKI keep the leaves RFC 5280-conformant too (same profile the RA
  # service applies to the certificates it issues at runtime).
  printf "%b" "${ext}subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid, issuer\n" > ${name}.ext
  openssl x509 -req -in ${name}.csr -CA CA.crt -CAkey CA.key -CAcreateserial \
    -days 365 -sha256 -extfile ${name}.ext -out ${name}.crt
}

echo "== VPP identity (vpp.*, VTN: TLS endpoint :8080 + DR-event signing) =="
issue vpp "/CN=VPP-VTN/O=VPP/C=ES" \
"basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n${TLS_SAN}\n"
openssl pkcs12 -export -inkey vpp.key -in vpp.crt -certfile CA.crt \
  -name vpp -out vpp.p12 -passout pass:${P12_PASS}

echo "== Manufacturer identity (server.*, internet-facing RA host :8081) =="
issue server "/CN=Manufacturer/O=Manufacturer/C=ES" \
"basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n${TLS_SAN}\n"

# The nominal power P is a manufacturing property, so the RA certifies it
# together with the public key: it travels in the subject DN as OU=P=<watts>.
# This is what stops an appliance from over-declaring its own capacity later
# (the owner proof repeats P, and the VPP checks both values match).
echo "== Appliance identity (VEN.*, factory-provisioned HSM signing key) =="
issue VEN "/CN=ven-0001/OU=P=2000/O=Appliances/C=ES" \
"basicConstraints = CA:FALSE\nkeyUsage = digitalSignature\nextendedKeyUsage = clientAuth\n"
openssl pkcs12 -export -inkey VEN.key -in VEN.crt -certfile CA.crt \
  -name ven -out VEN.p12 -passout pass:${P12_PASS}

echo
echo "== Verification =="
openssl x509 -in CA.crt -noout -subject -issuer
for c in vpp server VEN; do
  printf "%-12s " "${c}.crt:"; openssl verify -CAfile CA.crt ${c}.crt
done
echo "Done. P12 password: ${P12_PASS}"
