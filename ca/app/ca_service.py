"""The Certification Authority: the only module that holds the signing key.

It signs what the RA has validated, keeps the register of what it issued, and
publishes the CRL. It parses no request and applies no policy of its own beyond
the certificate profile.
"""
import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ReasonFlags

from . import registry

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
CA_CERT_FILE = CERTS_DIR / "CA.crt"
CA_KEY_FILE = CERTS_DIR / "CA.key"

_ca_cert = None
_ca_key = None

# A relying party whose copy is older than this must refresh it, and refuses to act if it cannot.
CRL_VALIDITY = datetime.timedelta(hours=24)
# The CRL distribution point written into every leaf. It must resolve for any client that follows
# it (Windows schannel does, and fails closed): loopback in development, the LAN address for a Pi.
CRL_URL = os.environ.get("TFG_CRL_URL", "http://127.0.0.1:8083/ra/crl")

# RFC 5280 reason codes by their RFC identifiers (keyCompromise, cACompromise, superseded, ...).
# "unspecified" is accepted but encoded as no reason at all, as the RFC asks. certificateHold is
# not offered: the register has no release path, so a hold here would be a permanent revocation.
REASONS = {f.value: f for f in ReasonFlags
           if f not in (ReasonFlags.unspecified, ReasonFlags.certificate_hold, ReasonFlags.remove_from_crl)}
REASONS["unspecified"] = None

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


def initialize() -> None:
    global _ca_cert, _ca_key
    _ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    _ca_key = serialization.load_pem_private_key(CA_KEY_FILE.read_bytes(), password=None)
    registry.initialize()


def certificate() -> x509.Certificate:
    return _ca_cert


def certificate_pem() -> str:
    return _ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries = []
    for n in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            entries.append(x509.DNSName(n))
    return x509.SubjectAlternativeName(entries)


def sign_leaf(csr: x509.CertificateSigningRequest, key_id: str, profile: str,
              san: list[str] | None, days: int, supersedes: str | None,
              now: datetime.datetime) -> dict:
    """Sign a leaf for an already validated CSR, record it, and supersede the serial a renewal replaces."""
    rules = PROFILES[profile]
    public_key = csr.public_key()
    serial = x509.random_serial_number()
    not_after = now + datetime.timedelta(days=days)

    # Extensions come from the profile, never from the CSR: the requester does not choose its own usage.
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(_ca_cert.subject)
        .public_key(public_key)
        .serial_number(serial)
        # Five minutes of slack: a relying party whose clock runs behind must not refuse a fresh certificate.
        .not_valid_before(now - datetime.timedelta(minutes=5))
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
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    registry.record(serial_hex, key_id, cert.subject.rfc4514_string(), now, not_after, pem, profile)
    if supersedes:
        registry.revoke(supersedes, "superseded", by=cert.subject.rfc4514_string())
    return {
        "certificate": pem,
        "subject": cert.subject.rfc4514_string(),
        "serial": serial_hex,
        "not_after": not_after.isoformat(),
    }


def revoke(serial: str, reason: str, by: str) -> bool:
    """Mark a serial revoked and move the CRL number. False if it was already revoked or never issued."""
    return registry.revoke(serial, reason, by=by)


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
