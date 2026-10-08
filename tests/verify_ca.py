import secrets
import sys
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent
CA_FILE = str(ROOT / "certs" / "CA.crt")
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


def spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main():
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())

    cn = f"ven-{secrets.token_hex(3)}"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Appliances"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    ])
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    print(f"Entity generated a local key pair and a CSR (CN={cn})\n")

    print("G1: RA issues a certificate from the CSR")
    r = requests.post(f"{CA}/ra/issue", json={"csr": csr_pem}, verify=CA_FILE)
    if not r.ok:
        die(f"/ra/issue -> {r.status_code} {r.text}")
    body = r.json()
    ok(f"/ra/issue -> subject={body['subject']} serial={body['serial']}")
    cert = x509.load_pem_x509_certificate(body["certificate"].encode())

    if chains_to_ca(cert, ca):
        ok("issued certificate chains to the CA")
    else:
        die("issued certificate does NOT chain to the CA")

    if spki(cert.public_key()) == spki(key.public_key()):
        ok("issued certificate certifies OUR public key (RA never saw the private key)")
    else:
        die("issued certificate carries a different public key")

    print("G2: leaf profile set by the RA (not copied from the CSR)")
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ok("basicConstraints CA:FALSE") if bc.ca is False else die("basicConstraints wrong")
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    ok("keyUsage digitalSignature") if ku.digital_signature else die("keyUsage wrong")
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    ok("extendedKeyUsage clientAuth") if ExtendedKeyUsageOID.CLIENT_AUTH in eku \
        else die("EKU wrong")

    print("G3: the issued certificate really certifies the entity's key")
    msg = f"{cn}|proof-of-possession".encode()
    sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    try:
        cert.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        ok("signature by the entity verifies under the issued certificate")
    except InvalidSignature:
        die("signature did not verify under the issued certificate")

    print("G4: RA rejects abuse")
    r = requests.post(f"{CA}/ra/issue", json={"csr": csr_pem}, verify=CA_FILE)
    ok("re-enrollment of the same key rejected (409)") if r.status_code == 409 \
        else die(f"expected 409 on re-enroll, got {r.status_code}")
    r = requests.post(f"{CA}/ra/issue", json={"csr": "-----not a csr-----"}, verify=CA_FILE)
    ok("malformed CSR rejected (400)") if r.status_code == 400 \
        else die(f"expected 400 on bad CSR, got {r.status_code}")
    # A well-formed CSR proving possession of a new key is not enough for a name already live.
    intruder = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    same_name = (x509.CertificateSigningRequestBuilder().subject_name(subject)
                 .sign(intruder, hashes.SHA256()))
    r = requests.post(f"{CA}/ra/issue",
                      json={"csr": same_name.public_bytes(serialization.Encoding.PEM).decode()},
                      verify=CA_FILE)
    ok(f"a second live certificate for the same subject refused (409): {r.json().get('detail', '')[:60]}") \
        if r.status_code == 409 and "subject" in r.text \
        else die(f"expected 409 on subject collision, got {r.status_code} {r.text}")

    print(f"\nCERTIFICATE ISSUANCE COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
