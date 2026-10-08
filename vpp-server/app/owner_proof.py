import base64

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from . import crypto_service


class InvalidOwnerProof(Exception):
    """Malformed proof, bad signature, or appliance not certified by the CA."""


class OwnershipMismatch(Exception):
    """The proof binds the appliance to a different user than the authenticated one."""


def certified_nominal_power(certificate: x509.Certificate) -> int:
    for attribute in certificate.subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME
    ):
        if attribute.value.startswith("P="):
            return int(attribute.value[2:])
    raise InvalidOwnerProof(
        "appliance certificate carries no certified nominal power (OU=P=...)"
    )


def verify(jws_token: str, authenticated_user: str) -> dict:
    """Verify the proof and return the binding; `authenticated_user` is the mTLS identity."""
    try:
        header = jwt.get_unverified_header(jws_token)
    except Exception as e:
        raise InvalidOwnerProof(f"not a JWS: {e}")
    x5c = header.get("x5c")
    if not x5c:
        raise InvalidOwnerProof("owner proof carries no appliance certificate (x5c)")
    ven_cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))

    if not crypto_service.issued_by_ca(ven_cert):
        raise InvalidOwnerProof("appliance certificate not issued by the CA")
    if not crypto_service.within_validity(ven_cert):
        raise InvalidOwnerProof("appliance certificate expired or not yet valid")

    ven_pub = ven_cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        payload = jwt.decode(jws_token, ven_pub, algorithms=["RS256"])
    except Exception as e:
        raise InvalidOwnerProof(f"appliance signature invalid: {e}")

    certified_power = certified_nominal_power(ven_cert)
    if payload.get("P") != certified_power:
        raise InvalidOwnerProof(
            f"declared power {payload.get('P')} does not match the certified "
            f"{certified_power}"
        )

    if payload.get("owner") != authenticated_user:
        raise OwnershipMismatch(
            f"proof binds the appliance to {payload.get('owner')}, "
            f"not to the authenticated user {authenticated_user}"
        )

    return {
        "ven_subject": ven_cert.subject.rfc4514_string(),
        "owner": authenticated_user,
        "cert_pem": ven_cert.public_bytes(serialization.Encoding.PEM).decode(),
        "nominal_power": certified_power,
        "max_curtail": payload.get("max"),
        "recovery": payload.get("rec"),
    }
