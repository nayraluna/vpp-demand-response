"""The Registration Authority: validates every request, holds no key.

It checks what a request proves (possession of the key, a valid signer, the
operator role) and what the register allows (no duplicate key, one live
certificate per subject), then hands the approved request to the CA to sign.
"""
import base64
import datetime

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from . import ca_service, registry


class InvalidCSR(Exception):
    """The CSR is malformed or its self-signature does not verify."""


class AlreadyEnrolled(Exception):
    """A certificate was already issued for this public key."""


class InvalidRequest(Exception):
    """A signed request that is malformed or signed by a certificate this CA no longer stands behind."""


class NotOperator(Exception):
    """A valid platform identity, but not one allowed to revoke."""


def _public_key_id(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def issue_from_csr(csr_pem: str, days: int = 365, profile: str = "client",
                   san: list[str] | None = None, supersedes: str | None = None) -> dict:
    """Validate a CSR and have the CA issue a leaf; `supersedes` names the serial a renewal replaces."""
    if profile not in ca_service.PROFILES:
        raise InvalidCSR(f"unknown certificate profile {profile!r}")
    if san and not profile.startswith("tls-server"):
        raise InvalidCSR("only a TLS server certificate carries subjectAltName")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise InvalidCSR(f"could not parse CSR: {e}")

    # Proof of possession: the CSR must be signed by the key it carries.
    if not csr.is_signature_valid:
        raise InvalidCSR("CSR self-signature does not verify")
    if not csr.subject.rdns:
        raise InvalidCSR("CSR has an empty subject")
    if sorted((a.oid.dotted_string, a.value) for a in csr.subject) == \
            sorted((a.oid.dotted_string, a.value) for a in ca_service.certificate().subject):
        raise InvalidCSR("CSR asks for the CA's own name")

    key_id = _public_key_id(csr.public_key())
    already = registry.serial_for_key(key_id)
    if already:
        raise AlreadyEnrolled(f"public key already enrolled (serial {already})")

    # Possession of a key proves nothing about the name in the CSR: without this a fresh key
    # could be certified under an existing identity. Only the serial a renewal replaces may be live.
    now = datetime.datetime.now(datetime.timezone.utc)
    supersedes = registry.normalize_serial(supersedes) if supersedes else None
    live = registry.live_serial_for_subject(csr.subject.rfc4514_string(), now)
    if live and live != supersedes:
        raise AlreadyEnrolled(f"subject already holds a live certificate (serial {live})")

    return ca_service.sign_leaf(csr, key_id, profile, san, days, supersedes, now)


def refuse_requested_role(csr_pem: str) -> None:
    """The online endpoint issues plain identities. A role is granted on the CA host, at setup."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception:
        return  # issue_from_csr reports the parse error
    for attr in csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME):
        if attr.value.strip().lower().startswith("role="):
            raise InvalidCSR("a role is granted on the CA host, it cannot be requested online")


def _issued_here(cert: x509.Certificate) -> bool:
    """Signed by this CA, the root still valid, the leaf an end entity that may sign."""
    root = ca_service.certificate()
    try:
        cert.verify_directly_issued_by(root)
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (root.not_valid_before_utc <= now <= root.not_valid_after_utc):
            return False
        if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
        # The leaf must be an end entity allowed to sign, not a CA certificate used as one.
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    except Exception:
        return False


def _verify_signed_request(token: str) -> tuple[x509.Certificate, dict]:
    """Verify a JWS against the certificate in its x5c: issued here, within validity, not revoked."""
    try:
        header = jwt.get_unverified_header(token)
        signer = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    except Exception as e:
        raise InvalidRequest(f"not a signed request: {e}")
    if not _issued_here(signer):
        raise InvalidRequest("signer not certified by this CA")
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (signer.not_valid_before_utc <= now <= signer.not_valid_after_utc):
        raise InvalidRequest("signer certificate is outside its validity period")
    if registry.is_revoked(format(signer.serial_number, "x")):
        raise InvalidRequest("signer certificate is revoked")
    signer_pub = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        payload = jwt.decode(token, signer_pub, algorithms=["RS256", "ES256"])
    except Exception as e:
        raise InvalidRequest(f"request signature invalid: {e}")
    return signer, payload


def verify_revocation_request(token: str) -> dict:
    """Only an operator may revoke. Returns the order to execute."""
    signer, payload = _verify_signed_request(token)
    roles = [a.value for a in signer.subject.get_attributes_for_oid(
        NameOID.ORGANIZATIONAL_UNIT_NAME)]
    if "role=operator" not in roles:
        raise NotOperator("signer does not carry the operator role")
    serial = payload.get("serial")
    if not isinstance(serial, str) or not serial:
        raise InvalidRequest("request must name the serial to revoke")
    try:
        serial = registry.normalize_serial(serial)
    except ValueError as e:
        raise InvalidRequest(str(e))
    reason = str(payload.get("reason") or "unspecified")
    if reason not in ca_service.REASONS:
        raise InvalidRequest(f"unknown revocation reason {reason!r}, use one of {sorted(ca_service.REASONS)}")
    return {"serial": serial, "reason": reason,
            "requested_by": signer.subject.rfc4514_string()}


def renew_from_request(token: str) -> dict:
    """Re-key: a valid holder signs a CSR for a new key, same subject; the old serial is superseded."""
    signer, payload = _verify_signed_request(token)
    csr_pem = payload.get("csr")
    if not isinstance(csr_pem, str):
        raise InvalidRequest("request must carry the CSR for the new key")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise InvalidRequest(f"could not parse CSR: {e}")
    if csr.subject != signer.subject:
        raise InvalidRequest("renewal cannot change the subject")
    spki = lambda k: k.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    if spki(csr.public_key()) == spki(signer.public_key()):
        raise AlreadyEnrolled("renewal must use a new key pair")

    old_serial = format(signer.serial_number, "x")
    issued = issue_from_csr(csr_pem, supersedes=old_serial)
    return {**issued, "superseded": old_serial, "crl_number": registry.crl_number()}
