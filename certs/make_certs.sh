#!/usr/bin/env bash
# Builds the platform PKI
#
#   CA.key / CA.crt               self-signed root, the common trust anchor
#   vpp.key / vpp.crt / vpp.p12   VPP (VTN)
#   server.key / server.crt       CA TLS service
#   VEN.key / VEN.crt / VEN.p12   appliance (VEN)
#
# Run from certs/:  bash make_certs.sh
set -e

# Do not remove. PostgreSQL leaves a stale OPENSSL_CONF that makes openssl
# abort, and Git Bash rewrites the -subj arguments into Windows paths.
unset OPENSSL_CONF
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# Placeholder, not a secret. The bundles it protects are local and gitignored.
P12_PASS="${P12_PASS:-changeit}"

# To reach the services from a real phone or a Pi, add this machine's address:
#   EXTRA_SAN_IPS="192.168.1.50" bash make_certs.sh
TLS_SAN="subjectAltName = DNS:localhost, IP:127.0.0.1, IP:10.0.2.2"
if [ -n "${EXTRA_SAN_IPS:-}" ]; then
  IFS=',' read -ra _extra <<< "$EXTRA_SAN_IPS"
  for _ip in "${_extra[@]}"; do
    _ip="$(echo "$_ip" | tr -d '[:space:]')"
    [ -n "$_ip" ] && TLS_SAN="$TLS_SAN, IP:$_ip"
  done
fi

# The extensions are explicit because Python 3.13 rejects a root without
# keyUsage, and the appliance runs 3.13.
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
  printf "%b" "${ext}subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid, issuer\n" > ${name}.ext
  openssl x509 -req -in ${name}.csr -CA CA.crt -CAkey CA.key -CAcreateserial \
    -days 365 -sha256 -extfile ${name}.ext -out ${name}.crt
}

issue vpp "/CN=VPP-VTN/O=VPP/C=ES" \
"basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n${TLS_SAN}\n"
openssl pkcs12 -export -inkey vpp.key -in vpp.crt -certfile CA.crt \
  -name vpp -out vpp.p12 -passout pass:${P12_PASS}

issue server "/CN=Manufacturer/O=Manufacturer/C=ES" \
"basicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n${TLS_SAN}\n"

# The nominal power is certified in the subject as OU=P=<watts>. The VPP checks
# it against the value the appliance signs, so it cannot over-declare capacity.
# In production this key would never leave the appliance HSM.
issue VEN "/CN=ven-0001/OU=P=2000/O=Appliances/C=ES" \
"basicConstraints = CA:FALSE\nkeyUsage = digitalSignature\nextendedKeyUsage = clientAuth\n"
openssl pkcs12 -export -inkey VEN.key -in VEN.crt -certfile CA.crt \
  -name ven -out VEN.p12 -passout pass:${P12_PASS}

echo
openssl x509 -in CA.crt -noout -subject -issuer
for c in vpp server VEN; do
  printf "%-12s " "${c}.crt:"; openssl verify -CAfile CA.crt ${c}.crt
done
echo "Done. P12 password: ${P12_PASS}"
