import datetime
import sys
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import chain as pki_chain  # noqa: E402
from pki import jws as pki_jws  # noqa: E402

CERTS_DIR = ROOT_DIR / "certs"
KEY_FILE = CERTS_DIR / "vpp.key"
CERT_FILE = CERTS_DIR / "vpp.crt"
ROOT_CERT_FILE = CERTS_DIR / "CA.crt"
# The issuing certificates are public: they let the VPP build a path for a certificate that
# arrived without its chain, such as a client certificate read off the TLS socket.
ISSUING_CERT_FILES = (CERTS_DIR / "platform-ca.crt", CERTS_DIR / "device-ca.crt")

_private_key = None
_chain: list[x509.Certificate] = []
_root = None
_issuing: list[x509.Certificate] = []


def initialize() -> None:
    global _private_key, _chain, _root, _issuing
    try:
        _private_key = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
        _chain = pki_chain.load_pem_chain(CERT_FILE.read_bytes())
        _root = x509.load_pem_x509_certificate(ROOT_CERT_FILE.read_bytes())
        _issuing = [x509.load_pem_x509_certificate(f.read_bytes()) for f in ISSUING_CERT_FILES]
    except FileNotFoundError as e:
        raise RuntimeError(f"VPP not provisioned: {e.filename} missing, run provision.py")


def root() -> x509.Certificate:
    return _root


def issuing_cas() -> list[x509.Certificate]:
    return list(_issuing)


def issuer_of(cert: x509.Certificate, carried: list[x509.Certificate] = ()) -> x509.Certificate | None:
    """The issuing CA under which `cert` chains to the root, or None. `carried` is the x5c tail."""
    return pki_chain.issued_under(cert, list(carried) + _issuing, _root)


def issued_by_ca(cert: x509.Certificate, carried: list[x509.Certificate] = ()) -> bool:
    return issuer_of(cert, carried) is not None


def within_validity(cert: x509.Certificate) -> bool:
    """Expired certs drop out of the CRL, so a revoked one would be accepted again without this."""
    return pki_chain.within_validity(cert)


def subject() -> str:
    return _chain[0].subject.rfc4514_string()


def certificate_pem() -> str:
    """The VPP certificate with its issuing CA, so a receiver can build the path from the root alone."""
    return "".join(pki_chain.pem(c) for c in _chain)


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


def jws_algorithm(key) -> str:
    """ES256 for an EC key, RS256 for RSA: the key decides, the code does not."""
    return pki_jws.algorithm_for(key)


def sign_jws(payload: dict) -> str:
    """Compact JWS carrying the VPP certificate chain in x5c so the verifier can chain it to the root."""
    return pki_jws.sign(payload, _private_key, _chain, "application/dr-event+json")


def verify_signer(token: str) -> tuple[x509.Certificate, x509.Certificate, dict]:
    """Shared path of every artefact verifier: the signer from x5c, its chain to the root, the payload.

    Returns (signer, issuing CA, payload). Raises ValueError with the reason to refuse.
    """
    try:
        certs = pki_chain.x5c_chain(jwt.get_unverified_header(token))
        signer = certs[0]
    except Exception as e:
        raise ValueError(f"carries no signer certificate (x5c): {e}")
    issuer = issuer_of(signer, certs[1:])
    if issuer is None:
        raise ValueError("certificate not issued under the platform root")
    if not within_validity(signer):
        raise ValueError("certificate expired or not yet valid")
    try:
        payload = pki_jws.decode_with(token, signer)
    except Exception as e:
        raise ValueError(f"signature invalid: {e}")
    return signer, issuer, payload
