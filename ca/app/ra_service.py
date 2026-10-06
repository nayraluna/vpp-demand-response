import base64
import datetime
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from . import registry

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
CA_CERT_FILE = CERTS_DIR / "CA.crt"
CA_KEY_FILE = CERTS_DIR / "CA.key"

_ca_cert = None
_ca_key = None


class InvalidCSR(Exception):
    """The CSR is malformed or its self-signature does not verify."""


class AlreadyEnrolled(Exception):
    """A certificate was already issued for this public key."""


class InvalidRequest(Exception):
    """A signed request (revocation, renewal) that is malformed, unsigned, or
    signed by a certificate this CA does not stand behind any more."""


class NotOperator(Exception):
    """A valid platform identity, but not one allowed to revoke."""


# How long a published list stays valid. A relying party whose copy is older
# than this must refresh it, and refuses to act if it cannot.
CRL_VALIDITY = datetime.timedelta(hours=24)


def initialize() -> None:
    global _ca_cert, _ca_key
    _ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    _ca_key = serialization.load_pem_private_key(CA_KEY_FILE.read_bytes(), password=None)
    registry.initialize()


def ca_certificate_pem() -> str:
    return _ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def _public_key_id(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def issue_from_csr(csr_pem: str, days: int = 365) -> dict:
    """Verify a CSR and issue a CA-signed leaf certificate for a platform identity."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise InvalidCSR(f"could not parse CSR: {e}")

    # Proof of possession: the CSR must be signed by the private key matching the
    # public key it carries. This is what makes a CSR trustworthy to the RA.
    if not csr.is_signature_valid:
        raise InvalidCSR("CSR self-signature does not verify")

    public_key = csr.public_key()
    key_id = _public_key_id(public_key)
    already = registry.serial_for_key(key_id)
    if already:
        raise AlreadyEnrolled(f"public key already enrolled (serial {already})")

    serial = x509.random_serial_number()
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=days)

    # RA policy: a leaf VEN signing identity. Extensions are set by the RA, NOT
    # copied blindly from the CSR (the requester does not get to choose them).
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(_ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_ca_cert.public_key()),
            critical=False,
        )
        .sign(_ca_key, hashes.SHA256())
    )

    serial_hex = format(serial, "x")
    registry.record(serial_hex, key_id, cert.subject.rfc4514_string(), now, not_after)
    return {
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "subject": cert.subject.rfc4514_string(),
        "serial": serial_hex,
        "not_after": not_after.isoformat(),
    }


def _issued_here(cert: x509.Certificate) -> bool:
    try:
        _ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def _verify_signed_request(token: str) -> tuple[x509.Certificate, dict]:
    """Common ground for every request the CA accepts over plain TLS: a JWS
    whose x5c carries the requester's own certificate. The :8081 listener has
    no client certificates, so the request must carry its own proof of who is
    asking, the same way the pairing bundle and the calendar do. Checked in
    order: the signer was issued here, is still within its validity, has not
    been revoked, and the signature verifies against it."""
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
    return {"serial": serial,
            "reason": str(payload.get("reason") or "unspecified"),
            "requested_by": signer.subject.rfc4514_string()}


def renew_from_request(token: str) -> dict:
    """Renewal is re-keying: the holder of a valid certificate signs a request
    carrying a CSR for a NEW key pair, and receives a certificate with the same
    subject. The old certificate is revoked as superseded in the same act, so
    one identity never has two live certificates. A holder whose certificate
    has expired or been revoked cannot renew and re-enrols from scratch, with
    the identity proof, which is the right path for a lost credential."""
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

    issued = issue_from_csr(csr_pem)
    old_serial = format(signer.serial_number, "x")
    registry.revoke(old_serial, "superseded")
    return {**issued, "superseded": old_serial, "crl_number": registry.crl_number()}


def crl_jws() -> str:
    """The revocation list, signed with the CA key. Relying parties already hold
    the CA certificate as their trust anchor, so they verify straight against it
    and no x5c is needed. It carries this_update and next_update like an X.509
    CRL, plus the monotonic crl_number so a stale list can be refused."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "issuer": _ca_cert.subject.rfc4514_string(),
        "crl_number": registry.crl_number(),
        "this_update": now.isoformat(),
        "next_update": (now + CRL_VALIDITY).isoformat(),
        "revoked": registry.revoked(now),
    }
    key_pem = _ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256",
                      headers={"typ": "application/crl+json"})
