"""Certificate chain validation against the platform root.

The hierarchy is root -> issuing CA -> leaf. A verifier holds the root alone and
learns the issuing CA from the artefact (x5c) or from the issuing certificates it
was provisioned with.
"""
import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class ChainError(Exception):
    """The certificate does not chain to the root under the platform's rules."""


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def within_validity(cert: x509.Certificate, now: datetime.datetime | None = None) -> bool:
    """Expired certificates drop out of the CRL, so a revoked one would be accepted again without this."""
    now = now or now_utc()
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def load_pem_chain(pem: str | bytes) -> list[x509.Certificate]:
    """Every certificate in a PEM file, the leaf first."""
    data = pem.encode() if isinstance(pem, str) else pem
    return x509.load_pem_x509_certificates(data)


def x5c_chain(header: dict) -> list[x509.Certificate]:
    """The certificates of a JWS x5c header, the signer first."""
    return [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header.get("x5c") or []]


def serial_hex(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def _is_ca(cert: x509.Certificate, max_path_length: int | None) -> bool:
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if not bc.ca:
        return False
    if max_path_length is not None and (bc.path_length is None or bc.path_length > max_path_length):
        return False
    return cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign


def _is_signing_leaf(cert: x509.Certificate) -> bool:
    if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        return False
    return cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature


def verify_chain(leaf: x509.Certificate, candidates: list[x509.Certificate],
                 root: x509.Certificate, now: datetime.datetime | None = None) -> x509.Certificate:
    """Validate leaf -> issuing CA -> root and return the issuing CA.

    `candidates` are the issuing certificates the verifier knows or the artefact carried.
    The root must be a valid CA, the issuing CA a valid CA that may sign nothing but end
    entities (pathLen 0), and the leaf an end entity allowed to sign, all within validity.
    A leaf signed by the root directly is refused: issuance belongs to the issuing CAs.
    """
    now = now or now_utc()
    try:
        if not (_is_ca(root, None) and within_validity(root, now)):
            raise ChainError("root is not a valid CA")
        if not (_is_signing_leaf(leaf) and within_validity(leaf, now)):
            raise ChainError("not a valid end-entity certificate")
        for issuer in candidates:
            if issuer.subject != leaf.issuer:
                continue
            try:
                leaf.verify_directly_issued_by(issuer)
                issuer.verify_directly_issued_by(root)
            except Exception:
                continue
            if _is_ca(issuer, 0) and within_validity(issuer, now):
                return issuer
        raise ChainError("no path from the certificate to the root through an issuing CA")
    except ChainError:
        raise
    except Exception as e:  # malformed extensions, foreign schemes: fail closed
        raise ChainError(f"certificate cannot be validated: {e}")


def issued_under(leaf: x509.Certificate, candidates: list[x509.Certificate],
                 root: x509.Certificate) -> x509.Certificate | None:
    """The issuing CA if the leaf chains to the root, else None."""
    try:
        return verify_chain(leaf, candidates, root)
    except ChainError:
        return None


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def der_b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
