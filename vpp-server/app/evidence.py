import base64

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import crypto_service, db


class InvalidEvidence(Exception):
    """Malformed, unsigned, or not matching the activation it claims."""


class DuplicateEvidence(Exception):
    """Evidence for this activation was already accepted."""


def verify(jws_token: str, submitter_subject: str) -> dict:
    """Verify evidence submitted by `submitter_subject` (its mTLS identity)."""
    try:
        header = jwt.get_unverified_header(jws_token)
    except Exception as e:
        raise InvalidEvidence(f"not a JWS: {e}")
    x5c = header.get("x5c")
    if not x5c:
        raise InvalidEvidence("evidence carries no appliance certificate (x5c)")
    ven_cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))

    # (1) the signing appliance must be certified by the RA
    if not crypto_service.issued_by_ra(ven_cert):
        raise InvalidEvidence("appliance certificate not issued by the RA")

    # (2) the signature must verify under that certified key
    ven_pub = ven_cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        payload = jwt.decode(jws_token, ven_pub, algorithms=["RS256"])
    except Exception as e:
        raise InvalidEvidence(f"appliance signature invalid: {e}")

    # (3) the signer must be the appliance that opened this channel
    ven_subject = ven_cert.subject.rfc4514_string()
    if ven_subject != submitter_subject:
        raise InvalidEvidence(
            f"evidence signed by {ven_subject} but submitted by {submitter_subject}")

    # (4) it must refer to an activation actually issued to that appliance
    activation_id = payload.get("activation_id")
    activation = db.get_activation(activation_id) if activation_id else None
    if activation is None:
        raise InvalidEvidence(f"unknown activation {activation_id!r}")
    if activation["ven_subject"] != ven_subject:
        raise InvalidEvidence("activation was issued to a different appliance")
    # The nonce ties the evidence to that specific activation instance.
    if payload.get("nonce") != activation["nonce"]:
        raise InvalidEvidence("evidence does not carry the activation nonce")

    # (5) one execution may only be claimed once
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
