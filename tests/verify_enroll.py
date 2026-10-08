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
CA = "https://127.0.0.1:8081"

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
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:
        return False


def ra_issued_user_cert(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    r = requests.post(f"{CA}/ra/issue", json={"csr": csr_pem}, verify=CA_FILE)
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


def signed_by_ca(cn: str, days_ago: int = 0):
    """Minted with the CA key: fixtures the CA itself would refuse to issue."""
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())
    ca_key = serialization.load_pem_private_key((Path(CA_FILE).parent / "CA.key").read_bytes(), None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=days_ago + 1))
        .not_valid_after(now + datetime.timedelta(days=1 - days_ago))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


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
    ok("VPP returned Cert_VPP and it chains to the CA") \
        if chains_to_ca(vpp_cert, ca) else die("Cert_VPP does not chain to RA")

    print("G3: account persisted")
    r2 = requests.post(f"{VPP}/enroll", json={"certificate": user_cert}, verify=CA_FILE)
    ok("re-enroll of the same user -> already-enrolled (account persisted)") \
        if r2.json()["status"] == "already-enrolled" else die("account not persisted")

    print("G4: a certificate not issued by the CA is rejected")
    r3 = requests.post(f"{VPP}/enroll", json={"certificate": self_signed("rogue")},
                       verify=CA_FILE)
    ok("self-signed (foreign) certificate rejected (403)") \
        if r3.status_code == 403 else die(f"expected 403, got {r3.status_code}")

    print("G5: a genuine but expired certificate is rejected")
    _k, expired = signed_by_ca(f"expired-{secrets.token_hex(3)}", days_ago=2)
    r4 = requests.post(f"{VPP}/enroll", json={"certificate": expired}, verify=CA_FILE)
    ok(f"expired certificate rejected (403): {r4.json().get('detail', '')}") \
        if r4.status_code == 403 and "expired" in r4.text \
        else die(f"expected 403 expired, got {r4.status_code} {r4.text}")

    print("G6: a different certificate cannot take over an enrolled account")
    _k, twin = signed_by_ca(cn)
    r5 = requests.post(f"{VPP}/enroll", json={"certificate": twin}, verify=CA_FILE)
    ok(f"second live certificate for {cn} refused (409): {r5.json().get('detail', '')}") \
        if r5.status_code == 409 \
        else die(f"expected 409 on account takeover, got {r5.status_code} {r5.text}")

    print(f"\nUSER ENROLLMENT COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
