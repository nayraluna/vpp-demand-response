import base64

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crypto_service, db


class InvalidEvidence(Exception):
    """Malformed, unsigned, or not matching the activation it claims."""


class DuplicateEvidence(Exception):
    """Evidence for this activation was already accepted."""


def verify(jws_token: str, submitter_subject: str) -> dict:
    """Verify the evidence and return its fields; `submitter_subject` is the mTLS identity."""
    try:
        header = jwt.get_unverified_header(jws_token)
    except Exception as e:
        raise InvalidEvidence(f"not a JWS: {e}")
    x5c = header.get("x5c")
    if not x5c:
        raise InvalidEvidence("evidence carries no appliance certificate (x5c)")
    ven_cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))

    if not crypto_service.issued_by_ca(ven_cert):
        raise InvalidEvidence("appliance certificate not issued by the CA")
    if not crypto_service.within_validity(ven_cert):
        raise InvalidEvidence("appliance certificate expired or not yet valid")

    ven_pub = ven_cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        payload = jwt.decode(jws_token, ven_pub, algorithms=["RS256"])
    except Exception as e:
        raise InvalidEvidence(f"appliance signature invalid: {e}")

    ven_subject = ven_cert.subject.rfc4514_string()
    if ven_subject != submitter_subject:
        raise InvalidEvidence(
            f"evidence signed by {ven_subject} but submitted by {submitter_subject}")

    activation_id = payload.get("activation_id")
    activation = db.get_activation(activation_id) if activation_id else None
    if activation is None:
        raise InvalidEvidence(f"unknown activation {activation_id!r}")
    if activation["ven_subject"] != ven_subject:
        raise InvalidEvidence("activation was issued to a different appliance")

    if db.get_evidence(activation_id) is not None:
        raise DuplicateEvidence(
            f"evidence for {activation_id} was already accepted")

    reduction = payload.get("reduction_pct")
    if not isinstance(reduction, int) or not 0 < reduction <= 100:
        raise InvalidEvidence("reduction_pct must be an integer in (0, 100]")

    return {
        "activation_id": activation_id,
        "ven_subject": ven_subject,
        "executed_at": payload.get("executed_at"),
        "reduction_pct": reduction,
        "date": payload.get("date"),
        "time": payload.get("time"),
    }
