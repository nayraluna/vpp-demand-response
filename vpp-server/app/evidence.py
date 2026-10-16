from . import crypto_service, db, revocation


class InvalidEvidence(Exception):
    """Malformed, unsigned, or not matching the activation it claims."""


class DuplicateEvidence(Exception):
    """Evidence for this activation was already accepted."""


def verify(jws_token: str, submitter_subject: str) -> dict:
    """Verify the evidence and return its fields; `submitter_subject` is the mTLS identity."""
    try:
        ven_cert, issuer, payload = crypto_service.verify_signer(jws_token)
    except ValueError as e:
        raise InvalidEvidence(f"appliance certificate {e}")
    # Same subject as the channel is not the same certificate: a superseded one keeps the name.
    if revocation.is_revoked(ven_cert, issuer):
        raise InvalidEvidence("appliance certificate is revoked")

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
