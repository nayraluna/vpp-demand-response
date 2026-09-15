import base64
from pathlib import Path

import jwt  # PyJWT
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"
P12_FILE = CERTS_DIR / "VEN.p12"
P12_PASSWORD = b"changeit"

_private_key = None
_certificate = None


def initialize() -> None:
    global _private_key, _certificate
    with open(P12_FILE, "rb") as f:
        _private_key, _certificate, _chain = pkcs12.load_key_and_certificates(
            f.read(), P12_PASSWORD
        )
    if _private_key is None or _certificate is None:
        raise RuntimeError(f"Could not load VEN identity from {P12_FILE}")


def subject() -> str:
    return _certificate.subject.rfc4514_string()


def certificate_pem() -> str:
    return _certificate.public_bytes(serialization.Encoding.PEM).decode()


def nominal_power() -> int:
    """The nominal power P certified by the CA, read from the VEN
    certificate subject (OU=P=<watts>).

    P is certified rather than self-declared so that a compromised appliance
    cannot over-declare its capacity to claim a larger reward.
    """
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
    """Sign `payload` inside the HSM as a compact JWS (the PAS4 container).

    The VEN certificate travels in the x5c header so the VPP can verify the
    signature and chain it to the RA without knowing the appliance in advance.
    """
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
