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


def spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main():
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())

    # --- the entity generates its OWN key and a CSR (key never leaves here) ---
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "ven-0007"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Appliances"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        ]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    print("Entity generated a local key pair and a CSR (CN=ven-0007)\n")

    print("G1: RA issues a certificate from the CSR")
    r = requests.post(f"{MAN}/ra/issue", json={"csr": csr_pem}, verify=CA_FILE)
    if not r.ok:
        die(f"/ra/issue -> {r.status_code} {r.text}")
    body = r.json()
    ok(f"/ra/issue -> subject={body['subject']} serial={body['serial']}")
    cert = x509.load_pem_x509_certificate(body["certificate"].encode())

    if chains_to_ca(cert, ca):
        ok("issued certificate chains to the RA")
    else:
        die("issued certificate does NOT chain to the RA")

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
    msg = b"ven-0007|proof-of-possession"
    sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    try:
        cert.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        ok("signature by the entity verifies under the issued certificate")
    except InvalidSignature:
        die("signature did not verify under the issued certificate")

    print("G4: RA rejects abuse")
    r = requests.post(f"{MAN}/ra/issue", json={"csr": csr_pem}, verify=CA_FILE)
    ok("re-enrollment of the same key rejected (409)") if r.status_code == 409 \
        else die(f"expected 409 on re-enroll, got {r.status_code}")
    r = requests.post(f"{MAN}/ra/issue", json={"csr": "-----not a csr-----"}, verify=CA_FILE)
    ok("malformed CSR rejected (400)") if r.status_code == 400 \
        else die(f"expected 400 on bad CSR, got {r.status_code}")

    print(f"\nCERTIFICATE ISSUANCE COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
