import base64
import datetime
import os
from pathlib import Path

import ipaddress

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags

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
    """A signed request that is malformed or signed by a certificate this CA no longer stands behind."""


class NotOperator(Exception):
    """A valid platform identity, but not one allowed to revoke."""


# A relying party whose copy is older than this must refresh it, and refuses to act if it cannot.
CRL_VALIDITY = datetime.timedelta(hours=24)
# Where relying parties fetch the list; written into every leaf as its CRL distribution point.
CRL_URL = os.environ.get("TFG_CRL_URL", "https://127.0.0.1:8081/ra/crl")


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(w.capitalize() for w in rest)


# RFC 5280 reason codes by their usual names (keyCompromise, superseded, ...). "unspecified"
# is accepted but encoded as no reason at all, as the RFC asks.
REASONS = {_camel(f.name): f for f in ReasonFlags if f not in (ReasonFlags.unspecified, ReasonFlags.remove_from_crl)}
REASONS["unspecified"] = None


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


# The profile is picked by the CA from the channel the request came in on, never by the requester.
PROFILES = {
    "client": {"key_encipherment": False,
               "eku": [x509.ExtendedKeyUsageOID.CLIENT_AUTH]},
    "tls-server": {"key_encipherment": True,
                   "eku": [x509.ExtendedKeyUsageOID.SERVER_AUTH]},
    # The VPP: the same key is also provisioned for signing DR events.
    "tls-server+signing": {"key_encipherment": True,
                           "eku": [x509.ExtendedKeyUsageOID.SERVER_AUTH]},
}


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries = []
    for n in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            entries.append(x509.DNSName(n))
    return x509.SubjectAlternativeName(entries)


def issue_from_csr(csr_pem: str, days: int = 365, profile: str = "client",
                   san: list[str] | None = None, supersedes: str | None = None) -> dict:
    """Verify a CSR and issue a leaf certificate; `supersedes` names the serial a renewal replaces."""
    if profile not in PROFILES:
        raise InvalidCSR(f"unknown certificate profile {profile!r}")
    if san and not profile.startswith("tls-server"):
        raise InvalidCSR("only a TLS server certificate carries subjectAltName")
    rules = PROFILES[profile]
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except Exception as e:
        raise InvalidCSR(f"could not parse CSR: {e}")

    # Proof of possession: the CSR must be signed by the key it carries.
    if not csr.is_signature_valid:
        raise InvalidCSR("CSR self-signature does not verify")

    public_key = csr.public_key()
    key_id = _public_key_id(public_key)
    already = registry.serial_for_key(key_id)
    if already:
        raise AlreadyEnrolled(f"public key already enrolled (serial {already})")

    # Possession of a key proves nothing about the name in the CSR: without this a fresh key
    # could be certified under an existing identity. Only the serial a renewal replaces may be live.
    now = datetime.datetime.now(datetime.timezone.utc)
    live = registry.live_serial_for_subject(csr.subject.rfc4514_string(), now)
    if live and live != supersedes:
        raise AlreadyEnrolled(f"subject already holds a live certificate (serial {live})")

    serial = x509.random_serial_number()
    not_after = now + datetime.timedelta(days=days)

    # Extensions come from the profile, never from the CSR: the requester does not choose its own usage.
    builder = (
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
                # Key transport is an RSA notion; an EC key never enciphers.
                key_encipherment=rules["key_encipherment"] and isinstance(public_key, rsa.RSAPublicKey),
                data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage(rules["eku"]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_ca_cert.public_key()),
            critical=False,
        )
    )
    if san:
        builder = builder.add_extension(_san(san), critical=False)
    builder = builder.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(CRL_URL)],
        relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
    cert = builder.sign(_ca_key, hashes.SHA256())

    serial_hex = format(serial, "x")
    registry.record(serial_hex, key_id, cert.subject.rfc4514_string(), now, not_after)
    if supersedes:
        registry.revoke(supersedes, "superseded")
    return {
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "subject": cert.subject.rfc4514_string(),
        "serial": serial_hex,
        "not_after": not_after.isoformat(),
    }


def _issued_here(cert: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(_ca_cert)
        return True
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
    reason = str(payload.get("reason") or "unspecified")
    if reason not in REASONS:
        raise InvalidRequest(f"unknown revocation reason {reason!r}, use one of {sorted(REASONS)}")
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


def crl_der() -> bytes:
    """The RFC 5280 CRL signed with the CA key: CRLNumber, AKI, and a reason per entry."""
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(_ca_cert.subject)
               .last_update(now)
               .next_update(now + CRL_VALIDITY)
               .add_extension(x509.CRLNumber(registry.crl_number()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(_ca_cert.public_key()),
                              critical=False))
    for e in registry.revoked(now):
        entry = (x509.RevokedCertificateBuilder()
                 .serial_number(int(e["serial"], 16))
                 .revocation_date(datetime.datetime.fromisoformat(e["revoked_at"])))
        if REASONS.get(e["reason"]):
            entry = entry.add_extension(x509.CRLReason(REASONS[e["reason"]]), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(_ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
