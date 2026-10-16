"""The Certification Authorities: the only module that holds signing keys.

Three authorities. The root, offline, certifies the two issuing CAs and publishes the
list that revokes them. The platform issuing CA certifies the VPP, the operator and the
users. The device issuing CA certifies appliances, at the factory. Each issuing CA signs
what the RA has validated, keeps the register of what it issued, and publishes its CRL.
"""
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ReasonFlags

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import identity  # noqa: E402

from . import registry  # noqa: E402

CERTS_DIR = ROOT_DIR / "certs"
CA_DIR = Path(__file__).resolve().parent.parent

ROOT_CERT_FILE = CERTS_DIR / "CA.crt"
ROOT_KEY_FILE = CERTS_DIR / "CA.key"
ROOT_CRL_FILE = CERTS_DIR / "root.crl"

# A relying party whose copy is older than this must refresh it, and refuses to act if it cannot.
CRL_VALIDITY = datetime.timedelta(hours=24)
# The root is offline, so its list of revoked issuing CAs is re-signed on a longer cycle.
ROOT_CRL_VALIDITY = datetime.timedelta(days=180)
# Base of the CRL distribution points written into every certificate. It must resolve for any
# client that follows it (Windows schannel does, and fails closed): loopback in development.
CRL_BASE = os.environ.get("TFG_CRL_BASE", "http://127.0.0.1:8083/ra/crl")

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


class AlreadyEnrolled(Exception):
    """The register already holds a live certificate for this key or this subject."""


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries = []
    for n in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            entries.append(x509.DNSName(n))
    return x509.SubjectAlternativeName(entries)


def _key_id(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return digest.finalize().hex()


def _crl(issuer_cert: x509.Certificate, key, number: int, validity: datetime.timedelta,
         entries: list[dict], now: datetime.datetime) -> bytes:
    builder = (x509.CertificateRevocationListBuilder()
               .issuer_name(issuer_cert.subject)
               .last_update(now)
               .next_update(now + validity)
               .add_extension(x509.CRLNumber(number), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
                              critical=False))
    for e in entries:
        entry = (x509.RevokedCertificateBuilder()
                 .serial_number(int(e["serial"], 16))
                 .revocation_date(datetime.datetime.fromisoformat(e["revoked_at"])))
        if REASONS.get(e["reason"]):
            entry = entry.add_extension(x509.CRLReason(REASONS[e["reason"]]), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


class Issuer:
    """An issuing CA: a key, a certificate signed by the root, and a register of its own."""

    def __init__(self, name: str, cert_file: Path, key_file: Path, db_file: Path):
        self.name = name
        self.cert_file, self.key_file = cert_file, key_file
        self.register = registry.Register(db_file)
        self._cert = self._key = None

    def initialize(self, with_key: bool = True) -> "Issuer":
        self._cert = x509.load_pem_x509_certificate(self.cert_file.read_bytes())
        if with_key:
            self._key = identity.load_key(self.key_file)
        self.register.initialize()
        return self

    def certificate(self) -> x509.Certificate:
        return self._cert

    def sign_leaf(self, csr: x509.CertificateSigningRequest, profile: str, san: list[str] | None,
                  days: int, supersedes: str | None) -> dict:
        """Sign a leaf for a CSR the RA validated, record it, and supersede the serial a renewal replaces.

        The register's own rules apply here: a key is certified once, and a subject holds one
        live certificate, so an identity cannot be duplicated by requesting it again.
        """
        rules = PROFILES[profile]
        public_key = csr.public_key()
        key_id = _key_id(public_key)
        now = datetime.datetime.now(datetime.timezone.utc)

        already = self.register.serial_for_key(key_id)
        if already:
            raise AlreadyEnrolled(f"public key already enrolled (serial {already})")
        supersedes = registry.normalize_serial(supersedes) if supersedes else None
        live = self.register.live_serial_for_subject(csr.subject.rfc4514_string(), now)
        if live and live != supersedes:
            raise AlreadyEnrolled(f"subject already holds a live certificate (serial {live})")

        serial = x509.random_serial_number()
        not_after = now + datetime.timedelta(days=days)
        # Extensions come from the profile, never from the CSR: the requester does not choose its own usage.
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self._cert.subject)
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
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._cert.public_key()),
                           critical=False)
            .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(f"{CRL_BASE}/{self.name}")],
                relative_name=None, reasons=None, crl_issuer=None)]), critical=False)
        )
        if san:
            builder = builder.add_extension(_san(san), critical=False)
        cert = builder.sign(self._key, hashes.SHA256())

        serial_hex = format(serial, "x")
        leaf_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        self.register.record(serial_hex, key_id, cert.subject.rfc4514_string(), now, not_after,
                             leaf_pem, profile)
        if supersedes:
            self.register.revoke(supersedes, "superseded", by=cert.subject.rfc4514_string())
        return {
            # The chain travels with the leaf: a holder presents both, a verifier needs only the root.
            "certificate": leaf_pem + self._cert.public_bytes(serialization.Encoding.PEM).decode(),
            "subject": cert.subject.rfc4514_string(),
            "serial": serial_hex,
            "issuer": self.name,
            "not_after": not_after.isoformat(),
        }

    def revoke(self, serial: str, reason: str, by: str) -> bool:
        """Mark a serial revoked and move the CRL number. False if it was already revoked or never issued."""
        return self.register.revoke(serial, reason, by=by)

    def crl_der(self) -> bytes:
        """The RFC 5280 CRL signed with this issuer's key: CRLNumber, AKI, and a reason per entry."""
        now = datetime.datetime.now(datetime.timezone.utc)
        return _crl(self._cert, self._key, self.register.crl_number(), CRL_VALIDITY,
                    self.register.revoked(now), now)


ISSUERS = {
    "platform": Issuer("platform", CERTS_DIR / "platform-ca.crt", CERTS_DIR / "platform-ca.key",
                       CA_DIR / "platform.db"),
    "device": Issuer("device", CERTS_DIR / "device-ca.crt", CERTS_DIR / "device-ca.key",
                     CA_DIR / "device.db"),
}


def initialize(with_keys: bool = True) -> None:
    for issuer in ISSUERS.values():
        issuer.initialize(with_key=with_keys)


def root_certificate() -> x509.Certificate:
    return x509.load_pem_x509_certificate(ROOT_CERT_FILE.read_bytes())


def root_crl_der() -> bytes:
    """The root's list of revoked issuing CAs, signed offline and published as a file."""
    return ROOT_CRL_FILE.read_bytes()


def sign_root_crl(root_cert: x509.Certificate, root_key, register: registry.Register) -> bytes:
    """Offline act of the root: re-sign its list of revoked issuing CAs and publish it as a file."""
    now = datetime.datetime.now(datetime.timezone.utc)
    der = _crl(root_cert, root_key, register.crl_number(), ROOT_CRL_VALIDITY, register.revoked(now), now)
    ROOT_CRL_FILE.write_bytes(der)
    return der
