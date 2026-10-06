import base64
from pathlib import Path

import jwt  # PyJWT - JWS/JOSE container (PAS4)
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


def issued_by_ra(cert: x509.Certificate) -> bool:
    """True if `cert` was signed by the CA (i.e. it is a platform identity)."""
    try:
        _ca_certificate.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        # Fail closed: a bad signature, a foreign signature scheme, or a
        # malformed certificate all mean "not a platform identity".
        return False


def subject() -> str:
    return _certificate.subject.rfc4514_string()


def certificate_pem() -> str:
    return _certificate.public_bytes(serialization.Encoding.PEM).decode()


def sign(message: str) -> str:
    """Raw detached signature (hex). Pedagogical baseline for PAS3."""
    data = message.encode("utf-8")
    if isinstance(_private_key, rsa.RSAPrivateKey):
        sig = _private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(_private_key, ec.EllipticCurvePrivateKey):
        sig = _private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        raise RuntimeError("Unsupported key type")
    return sig.hex()


def _certificate_x5c() -> str:
    """The VPP certificate as a single standard-base64 DER string (JWS x5c)."""
    der = _certificate.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode()


def sign_jws(payload: dict) -> str:
    """Sign `payload` as a compact JWS (RFC 7515) - the PAS4 container.

    RS256 today (identical crypto to sign(): RSA PKCS#1 v1.5 + SHA-256); the
    VPP certificate travels in the x5c header so the verifier can pin it to the
    RA. When the signing key becomes EdDSA this switches to alg="EdDSA" with no
    other change to the container.
    """
    if not isinstance(_private_key, rsa.RSAPrivateKey):
        raise RuntimeError("sign_jws currently supports RS256 (RSA) only")
    key_pem = _private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    headers = {"typ": "application/dr-event+json", "x5c": [_certificate_x5c()]}
    return jwt.encode(payload, key_pem, algorithm="RS256", headers=headers)
