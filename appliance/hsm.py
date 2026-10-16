import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.x509.oid import NameOID

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import chain as pki_chain  # noqa: E402
from pki import jws as pki_jws  # noqa: E402

# Emulated HSM: the key is a file written by provision.py and read by nobody else.
CERTS_DIR = ROOT_DIR / "certs"
KEY_FILE = CERTS_DIR / "VEN.key"
CERT_FILE = CERTS_DIR / "VEN.crt"
# Factory root, the only trust anchor: a bundle proves itself against this, never one it brings.
CA_FILE = CERTS_DIR / "CA.crt"
# The platform issuing CA, public, installed at the factory so the appliance can build the path
# of an owner's credential that arrives without its chain.
PLATFORM_CA_FILE = CERTS_DIR / "platform-ca.crt"

_private_key = None
_chain: list[x509.Certificate] = []


def initialize() -> None:
    global _private_key, _chain
    try:
        _private_key = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
        _chain = pki_chain.load_pem_chain(CERT_FILE.read_bytes())
    except FileNotFoundError as e:
        raise RuntimeError(f"appliance not provisioned: {e.filename} missing, run provision.py")


def subject() -> str:
    return _chain[0].subject.rfc4514_string()


def trust_anchor() -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(CA_FILE.read_bytes())
    except FileNotFoundError:
        raise RuntimeError(f"appliance not provisioned: no factory root at {CA_FILE}")


def known_issuers() -> list[x509.Certificate]:
    """Issuing certificates the appliance holds from the factory, to complete a path when the artefact carries none."""
    try:
        return [x509.load_pem_x509_certificate(PLATFORM_CA_FILE.read_bytes())]
    except FileNotFoundError:
        return []


def certificate_pem() -> str:
    return pki_chain.pem(_chain[0])


def nominal_power() -> int:
    """P from the certificate subject (OU=P=<watts>): certified, so a compromised appliance cannot over-declare it."""
    return parse_nominal_power(_chain[0])


def parse_nominal_power(certificate) -> int:
    for attribute in certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME):
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
    """Compact JWS signed in the HSM, the VEN certificate and its issuing CA in x5c, so a verifier holding the root can chain it."""
    return pki_jws.sign(payload, _private_key, _chain, typ)
