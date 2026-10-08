import base64
import datetime
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
KEY_FILE = CERTS_DIR / "vpp.key"
CERT_FILE = CERTS_DIR / "vpp.crt"
CA_CERT_FILE = CERTS_DIR / "CA.crt"

_private_key = None
_certificate = None
_ca_certificate = None


def initialize() -> None:
    global _private_key, _certificate, _ca_certificate
    try:
        _private_key = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
        _certificate = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())
        _ca_certificate = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    except FileNotFoundError as e:
        raise RuntimeError(f"VPP not provisioned: {e.filename} missing, run provision.py")


def issued_by_ca(cert: x509.Certificate) -> bool:
    try:
        _ca_certificate.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False  # fail closed on bad signature, foreign scheme or malformed cert


def within_validity(cert: x509.Certificate) -> bool:
    """Expired certs drop out of the CRL, so a revoked one would be accepted again without this."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def subject() -> str:
    return _certificate.subject.rfc4514_string()


def certificate_pem() -> str:
    return _certificate.public_bytes(serialization.Encoding.PEM).decode()


def sign(message: str) -> str:
    """Raw detached signature, hex encoded."""
    data = message.encode("utf-8")
    if isinstance(_private_key, rsa.RSAPrivateKey):
        sig = _private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(_private_key, ec.EllipticCurvePrivateKey):
        sig = _private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise RuntimeError("Unsupported key type")
    return sig.hex()


def _certificate_x5c() -> str:
    """The VPP certificate as a base64 DER string for the JWS x5c header."""
    der = _certificate.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode()


def sign_jws(payload: dict) -> str:
    """Compact JWS (RS256) carrying the VPP certificate in x5c so the verifier can chain it to the CA."""
    if not isinstance(_private_key, rsa.RSAPrivateKey):
        raise RuntimeError("sign_jws currently supports RS256 (RSA) only")
    key_pem = _private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    headers = {"typ": "application/dr-event+json", "x5c": [_certificate_x5c()]}
    return jwt.encode(payload, key_pem, algorithm="RS256", headers=headers)
