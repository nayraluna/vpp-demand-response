import datetime
import secrets
import sys
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
CA_FILE = str(ROOT / "certs" / "CA.crt")
VPP = "https://127.0.0.1:8080"
MAN = "https://127.0.0.1:8081"

passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    sys.exit(1)


def chains_to_ca(cert, ca) -> bool:
    try:
        ca.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False


def ra_issued_user_cert(cn: str):
    """Entity-side: generate a key locally and get a user cert from the RA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    r = requests.post(f"{MAN}/ra/issue", json={"csr": csr_pem}, verify=CA_FILE)
    if not r.ok:
        die(f"RA /ra/issue -> {r.status_code} {r.text}")
    return key, r.json()["certificate"]


def self_signed(cn: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def main():
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())
    cn = f"user-{secrets.token_hex(3)}"

    print("G1: RA issues a user certificate")
    _key, user_cert = ra_issued_user_cert(cn)
    ok(f"RA issued a user certificate ({cn})")

    print("G2: user enrolls at the VPP")
    r = requests.post(f"{VPP}/enroll", json={"certificate": user_cert}, verify=CA_FILE)
    if not r.ok:
        die(f"/enroll -> {r.status_code} {r.text}")
    body = r.json()
    ok(f"account created (status={body['status']}, user={body['user']})") \
        if body["status"] == "enrolled" else die(f"unexpected status {body['status']}")

    vpp_cert = x509.load_pem_x509_certificate(body["vpp_certificate"].encode())
    ok("VPP returned Cert_VPP and it chains to the RA") \
        if chains_to_ca(vpp_cert, ca) else die("Cert_VPP does not chain to RA")

    print("G3: account persisted")
    r2 = requests.post(f"{VPP}/enroll", json={"certificate": user_cert}, verify=CA_FILE)
    ok("re-enroll of the same user -> already-enrolled (account persisted)") \
        if r2.json()["status"] == "already-enrolled" else die("account not persisted")

    print("G4: a certificate not issued by the RA is rejected")
    r3 = requests.post(f"{VPP}/enroll", json={"certificate": self_signed("rogue")},
                       verify=CA_FILE)
    ok("self-signed (non-RA) certificate rejected (403)") \
        if r3.status_code == 403 else die(f"expected 403, got {r3.status_code}")

    print(f"\nUSER ENROLLMENT COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
