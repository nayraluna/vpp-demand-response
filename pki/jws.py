"""Compact JWS carrying the signer's certificate chain in x5c."""
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .chain import der_b64

ALGORITHMS = ["ES256", "RS256"]  # the key decides, the verifier accepts both


def algorithm_for(key) -> str:
    return "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) else "RS256"


def sign(payload: dict, key, chain: list[x509.Certificate], typ: str) -> str:
    """Sign with `key`; x5c carries the signer's certificate first, then its issuing CA."""
    return jwt.encode(payload, key, algorithm=algorithm_for(key),
                      headers={"typ": typ, "x5c": [der_b64(c) for c in chain]})


def decode_with(token: str, signer: x509.Certificate) -> dict:
    """The payload, once the signature verifies under the signer's public key."""
    public = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return jwt.decode(token, public, algorithms=ALGORITHMS)
