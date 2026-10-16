"""The Registration Authority: validates every request, holds no key.

It checks what a request proves (possession of the key, a valid signer chaining to the
root, the operator role) and applies the platform's naming rules, then hands the approved
request to the platform issuing CA. It knows the root and the issuing certificates, which
are public, and reads the CRLs like any other relying party.
"""
import datetime
import sys
import threading
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import chain as pki_chain  # noqa: E402
from pki import jws as pki_jws  # noqa: E402

from . import ca_client, ca_service  # noqa: E402


class InvalidCSR(Exception):
    """The CSR is malformed or its self-signature does not verify."""


class InvalidRequest(Exception):
    """A signed request that is malformed or signed by a certificate the platform no longer stands behind."""


class NotOperator(Exception):
    """A valid platform identity, but not one allowed to revoke."""


_root = None
_issuing: list[x509.Certificate] = []
# Ids of the signed requests already served, kept until they expire: a captured request
# cannot be replayed inside its short life either. The life is bounded by the RA, not by
# the signer, so the memory cannot be grown by requests that claim to live for years.
_seen: dict[str, int] = {}
_seen_lock = threading.Lock()
MAX_REQUEST_LIFE = 600 + pki_jws.LEEWAY_SECONDS


def initialize() -> None:
    """Public material only: the root and the two issuing certificates."""
    global _root, _issuing
    _root = ca_service.root_certificate()
    _issuing = [x509.load_pem_x509_certificate(i.cert_file.read_bytes())
                for i in ca_service.ISSUERS.values()]


def root_pem() -> str:
    return pki_chain.pem(_root)


def issuing_pems() -> dict:
    return {name: pki_chain.pem(c) for name, c in zip(ca_service.ISSUERS, _issuing)}


def validate_csr(csr_pem: str, profile: str, san: list[str] | None) -> x509.CertificateSigningRequest:
    """The request-level checks: well formed, proof of possession, a name the platform accepts."""
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
    taken = [_root.subject, *(c.subject for c in _issuing)]
    if any(sorted((a.oid.dotted_string, a.value) for a in csr.subject) ==
           sorted((a.oid.dotted_string, a.value) for a in name) for name in taken):
        raise InvalidCSR("CSR asks for an authority's own name")
    return csr


def refuse_requested_role(csr_pem: str) -> None:
    """The online endpoint issues plain identities. A role is granted on the CA host, at setup."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception:
        return  # validate_csr reports the parse error
    for attr in csr.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME):
        if attr.value.strip().lower().startswith("role="):
            raise InvalidCSR("a role is granted on the CA host, it cannot be requested online")


def issue_from_csr(csr_pem: str, days: int = 365, profile: str = "client",
                   san: list[str] | None = None, supersedes: str | None = None) -> dict:
    """Validate, then ask the platform issuing CA to sign. Online issuance is platform credentials only."""
    validate_csr(csr_pem, profile, san)
    return ca_client.sign(csr_pem, profile, san, days, supersedes)


def _verify_signed_request(token: str, typ: str) -> tuple[x509.Certificate, dict]:
    """Verify a JWS against the certificate in its x5c: chains to the root, within validity, not revoked,
    of the expected type, short-lived, and not seen before."""
    try:
        header = jwt.get_unverified_header(token)
        certs = pki_chain.x5c_chain(header)
        signer = certs[0]
    except Exception as e:
        raise InvalidRequest(f"not a signed request: {e}")
    issuer = pki_chain.issued_under(signer, certs[1:] + _issuing, _root)
    if issuer is None:
        raise InvalidRequest("signer not certified under the platform root")
    now = datetime.datetime.now(datetime.timezone.utc)
    if not pki_chain.within_validity(signer, now):
        raise InvalidRequest("signer certificate is outside its validity period")
    if ca_client.is_revoked(signer, issuer):
        raise InvalidRequest("signer certificate is revoked")
    try:
        payload = pki_jws.decode_with(token, signer, typ=typ, require_exp=True)
    except pki_jws.WrongType as e:
        raise InvalidRequest(str(e))
    except Exception as e:
        raise InvalidRequest(f"request signature invalid, expired, or without expiry: {e}")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise InvalidRequest("request carries no identifier (jti)")
    now_ts = int(now.timestamp())
    if int(payload["exp"]) > now_ts + MAX_REQUEST_LIFE:
        raise InvalidRequest(f"request claims a life beyond {MAX_REQUEST_LIFE} s")
    with _seen_lock:
        for seen_id in [k for k, until in _seen.items() if until < now_ts]:
            del _seen[seen_id]
        if jti in _seen:
            raise InvalidRequest("request already served (replay)")
        _seen[jti] = int(payload["exp"]) + pki_jws.LEEWAY_SECONDS
    return signer, payload


def verify_revocation_request(token: str) -> dict:
    """Only an operator may revoke. Returns the order to execute."""
    signer, payload = _verify_signed_request(token, pki_jws.TYP_REVOCATION)
    roles = [a.value for a in signer.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)]
    if "role=operator" not in roles:
        raise NotOperator("signer does not carry the operator role")
    serial = payload.get("serial")
    if not isinstance(serial, str) or not serial:
        raise InvalidRequest("request must name the serial to revoke")
    try:
        serial = ca_service.registry.normalize_serial(serial)
    except ValueError as e:
        raise InvalidRequest(str(e))
    reason = str(payload.get("reason") or "unspecified")
    if reason not in ca_service.REASONS:
        raise InvalidRequest(f"unknown revocation reason {reason!r}, use one of {sorted(ca_service.REASONS)}")
    return {"serial": serial, "reason": reason, "requested_by": signer.subject.rfc4514_string()}


def renew_from_request(token: str) -> dict:
    """Re-key: a valid holder signs a CSR for a new key, same subject; the old serial is superseded."""
    signer, payload = _verify_signed_request(token, pki_jws.TYP_RENEWAL)
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
        raise ca_client.Refused(409, "renewal must use a new key pair")
    old_serial = format(signer.serial_number, "x")
    issued = issue_from_csr(csr_pem, supersedes=old_serial)
    return {**issued, "superseded": old_serial}
