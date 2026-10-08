import base64
from pathlib import Path

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.x509.oid import NameOID

# Emulated HSM: the key is a file written by provision.py and read by nobody else.
CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"
KEY_FILE = CERTS_DIR / "VEN.key"
CERT_FILE = CERTS_DIR / "VEN.crt"
# Factory root, the only trust anchor: a bundle proves itself against this, never one it brings.
CA_FILE = CERTS_DIR / "CA.crt"

_private_key = None
_certificate = None


def initialize() -> None:
    global _private_key, _certificate
    try:
        _private_key = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
        _certificate = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())
    except FileNotFoundError as e:
        raise RuntimeError(f"appliance not provisioned: {e.filename} missing, run provision.py")


def subject() -> str:
    return _certificate.subject.rfc4514_string()


def trust_anchor():
    try:
        return x509.load_pem_x509_certificate(CA_FILE.read_bytes())
    except FileNotFoundError:
        raise RuntimeError(f"appliance not provisioned: no factory root at {CA_FILE}")


def certificate_pem() -> str:
    return _certificate.public_bytes(serialization.Encoding.PEM).decode()


def nominal_power() -> int:
    """P from the certificate subject (OU=P=<watts>): certified, so a compromised appliance cannot over-declare it."""
    return parse_nominal_power(_certificate)


def parse_nominal_power(certificate) -> int:
    for attribute in certificate.subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME
    ):
        value = attribute.value
        if value.startswith("P="):
            return int(value[2:])
    raise RuntimeError("certificate does not carry a certified nominal power (OU=P=...)")


def sign(message: str) -> str:
    data = message.encode("utf-8")
    if isinstance(_private_key, rsa.RSAPrivateKey):
        sig = _private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(_private_key, ec.EllipticCurvePrivateKey):
        sig = _private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise RuntimeError("Unsupported key type")
    return sig.hex()


def sign_jws(payload: dict, typ: str = "application/owner-proof+json") -> str:
    """Compact JWS signed in the HSM, VEN certificate in x5c so the VPP can chain it to the CA."""
    if not isinstance(_private_key, rsa.RSAPrivateKey):
        raise RuntimeError("sign_jws currently supports RS256 (RSA) only")
    key_pem = _private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    x5c = base64.b64encode(
        _certificate.public_bytes(serialization.Encoding.DER)
    ).decode()
    return jwt.encode(payload, key_pem, algorithm="RS256",
                      headers={"typ": typ, "x5c": [x5c]})
