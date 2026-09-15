import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
CA_CERT_FILE = CERTS_DIR / "CA.crt"
CA_KEY_FILE = CERTS_DIR / "CA.key"

_ca_cert = None
_ca_key = None
_issued: dict[str, str] = {}  # public-key SHA-256 -> serial, to reject re-enrollment (in-memory: resets on restart, a prototype simplification)


class InvalidCSR(Exception):
    """The CSR is malformed or its self-signature does not verify."""


class AlreadyEnrolled(Exception):
    """A certificate was already issued for this public key."""


def initialize() -> None:
    global _ca_cert, _ca_key
    _ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    _ca_key = serialization.load_pem_private_key(CA_KEY_FILE.read_bytes(), password=None)


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
    if key_id in _issued:
        raise AlreadyEnrolled(f"public key already enrolled (serial {_issued[key_id]})")

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
    _issued[key_id] = serial_hex
    return {
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "subject": cert.subject.rfc4514_string(),
        "serial": serial_hex,
        "not_after": not_after.isoformat(),
    }
