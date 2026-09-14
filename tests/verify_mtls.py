import datetime
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

import requests
from requests.exceptions import ConnectionError, SSLError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
CA_FILE = str(ROOT / "certs" / "CA.crt")
VPP = "https://127.0.0.1:8080"
MAN = "https://127.0.0.1:8081"
MTLS = "https://127.0.0.1:8443"

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="mtls_gate_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def write_pair(name: str, key, cert_pem: str):
    kf, cf = tmp / f"{name}.key", tmp / f"{name}.crt"
    kf.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    cf.write_text(cert_pem)
    return str(cf), str(kf)


def ra_cert(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(key, hashes.SHA256()))
    r = requests.post(f"{MAN}/ra/issue",
                      json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
                      verify=CA_FILE)
    if not r.ok:
        die(f"RA /ra/issue -> {r.status_code} {r.text}")
    return key, r.json()["certificate"]


def self_signed(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def main():
    try:
        print("G1: enrolled user gets an authenticated mutual-TLS session")
        key, cert = ra_cert(f"user-{secrets.token_hex(3)}")
        requests.post(f"{VPP}/enroll", json={"certificate": cert}, verify=CA_FILE)
        cf, kf = write_pair("user", key, cert)
        r = requests.get(f"{MTLS}/session", cert=(cf, kf), verify=CA_FILE)
        if r.status_code == 200 and r.json().get("authenticated"):
            ok(f"authenticated over mTLS as {r.json()['user']}")
        else:
            die(f"expected authenticated session, got {r.status_code} {r.text}")

        # Note on the exception type: with TLS 1.3 the server only rejects a
        # missing/untrusted client certificate after its own handshake flight,
        # so the client sees either an SSLError or the connection being closed
        # (ConnectionError). What matters is that the request never succeeds.
        print("G2: a client WITHOUT a certificate is rejected at the handshake")
        try:
            requests.get(f"{MTLS}/session", verify=CA_FILE)
            die("connection without a client cert was accepted")
        except (SSLError, ConnectionError) as e:
            ok(f"no-certificate client rejected ({type(e).__name__})")

        print("G3: a NON-RA certificate is rejected at the handshake")
        sk, scert = self_signed("rogue")
        scf, skf = write_pair("rogue", sk, scert)
        try:
            requests.get(f"{MTLS}/session", cert=(scf, skf), verify=CA_FILE)
            die("self-signed client cert was accepted")
        except (SSLError, ConnectionError) as e:
            ok(f"non-RA (self-signed) client cert rejected ({type(e).__name__})")

        print("G4: an RA cert that was never enrolled is not authorized")
        gkey, gcert = ra_cert(f"ghost-{secrets.token_hex(3)}")  # NOT enrolled
        gcf, gkf = write_pair("ghost", gkey, gcert)
        r = requests.get(f"{MTLS}/session", cert=(gcf, gkf), verify=CA_FILE)
        ok("valid RA cert but no account -> 403") if r.status_code == 403 \
            else die(f"expected 403, got {r.status_code} {r.text}")

        print(f"\nMUTUAL TLS COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
