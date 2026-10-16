"""Compact JWS carrying the signer's certificate chain in x5c, with explicit type and freshness."""
import datetime
import secrets

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .chain import der_b64

ALGORITHMS = ["ES256", "RS256"]  # the key decides, the verifier accepts both
# Loosely synchronised clocks are a design assumption: this is how loose they may be.
LEEWAY_SECONDS = 120

# Every artefact declares what it is, and every verifier checks it (RFC 8725 explicit typing),
# so a token signed for one purpose cannot be presented for another.
TYP_PAIRING = "application/pairing+json"
TYP_OWNER_PROOF = "application/owner-proof+json"
TYP_AVAILABILITY = "application/availability+json"
TYP_EVIDENCE = "application/dr-evidence+json"
TYP_DR_EVENT = "application/dr-event+json"
TYP_REVOCATION = "application/revocation-request+json"
TYP_RENEWAL = "application/renewal-request+json"


class WrongType(Exception):
    """The token's typ header is not the one this verifier accepts."""


def algorithm_for(key) -> str:
    return "ES256" if isinstance(key, ec.EllipticCurvePrivateKey) else "RS256"


def fresh(payload: dict, ttl_seconds: int | None = None) -> dict:
    """Stamp a payload: when it was signed, a unique id, and, for one-shot requests, when it dies."""
    now = datetime.datetime.now(datetime.timezone.utc)
    stamped = {**payload, "iat": int(now.timestamp()), "jti": secrets.token_hex(8)}
    if ttl_seconds is not None:
        stamped["exp"] = int((now + datetime.timedelta(seconds=ttl_seconds)).timestamp())
    return stamped


def sign(payload: dict, key, chain: list[x509.Certificate], typ: str,
         ttl_seconds: int | None = None) -> str:
    """Sign with `key`; x5c carries the signer's certificate first, then its issuing CA."""
    return jwt.encode(fresh(payload, ttl_seconds), key, algorithm=algorithm_for(key),
                      headers={"typ": typ, "x5c": [der_b64(c) for c in chain]})


def decode_with(token: str, signer: x509.Certificate, typ: str | None = None,
                require_exp: bool = False) -> dict:
    """The payload, once the signature verifies under the signer's public key.

    Checks the typ header when one is expected, and the timing claims PyJWT knows:
    `exp` must lie ahead and `iat` must not lie ahead, both within the leeway. One-shot
    requests must carry `exp`, so a captured one dies on its own.
    """
    if typ is not None and jwt.get_unverified_header(token).get("typ") != typ:
        raise WrongType(f"token is not {typ}")
    public = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    options = {"require": ["exp"]} if require_exp else {}
    return jwt.decode(token, public, algorithms=ALGORITHMS, leeway=LEEWAY_SECONDS, options=options)
