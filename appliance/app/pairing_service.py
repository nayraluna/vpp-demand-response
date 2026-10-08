import base64
import datetime
import sys
from pathlib import Path

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import hsm  # noqa: E402

from . import config as device_config  # noqa: E402


class InvalidBundle(Exception):
    """The onboarding bundle is malformed, unsigned, or not owned by an RA user."""


class AlreadyPaired(Exception):
    """Already in state 1, a factory reset is required first."""


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Signed by the issuer, the issuer still a valid CA, the leaf an end entity that may sign."""
    try:
        cert.verify_directly_issued_by(issuer)
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc):
            return False
        if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
        # The leaf must be an end entity allowed to sign, not a CA certificate used as one.
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    except Exception:
        # Fail closed: any verification error means "not issued by this issuer".
        return False


def _within_validity(cert: x509.Certificate) -> bool:
    """Expired certificates drop off the CRL, so this keeps a withdrawn credential refused past its expiry."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def pair(jws_token: str) -> dict:
    cfg = device_config.load()
    if cfg["state"] != 0:
        raise AlreadyPaired(f"appliance already paired with {cfg['owner']}")

    try:
        header = jwt.get_unverified_header(jws_token)
    except Exception as e:
        raise InvalidBundle(f"not a JWS: {e}")
    x5c = header.get("x5c")
    if not x5c:
        raise InvalidBundle("bundle has no owner certificate (x5c)")
    owner = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))

    owner_pub = owner.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        payload = jwt.decode(jws_token, owner_pub, algorithms=["RS256", "ES256"])
    except Exception as e:
        raise InvalidBundle(f"owner signature invalid: {e}")

    # Any cert_ra in the bundle is ignored: a root received over the channel it protects
    # would let anyone on the LAN enrol an unpaired appliance into a VPP of their own.
    root = hsm.trust_anchor()
    try:
        cert_vpp = x509.load_pem_x509_certificate(payload["cert_vpp"].encode())
    except Exception as e:
        raise InvalidBundle(f"missing/invalid VPP certificate in bundle: {e}")
    if not _issued_by(owner, root):
        raise InvalidBundle("owner certificate not issued by the platform CA")
    if not _within_validity(owner):
        raise InvalidBundle("owner certificate expired or not yet valid")
    if not _issued_by(cert_vpp, root):
        raise InvalidBundle("VPP certificate not issued by the platform CA")
    if not _within_validity(cert_vpp):
        raise InvalidBundle("VPP certificate expired or not yet valid")

    owner_subject = owner.subject.rfc4514_string()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    here = Path(__file__).resolve().parent.parent
    vpp_file = here / "trust_vpp.pem"
    vpp_file.write_text(payload["cert_vpp"])
    cfg.update({
        "state": 1,
        "vpp_url": payload.get("vpp_url"),
        "vpp_mtls_url": payload.get("vpp_mtls_url"),
        "owner": owner_subject,
        "owner_serial": format(owner.serial_number, "x"),
        "paired_at": now,
        "vpp_cert_file": str(vpp_file),
    })
    device_config.save(cfg)

    parameters = {
        "P": hsm.nominal_power(),   # certified by the CA, not self-declared
        "max": cfg["max"],
        "rec": cfg["rec"],
    }
    owner_proof = hsm.sign_jws({
        "ven": hsm.subject(),
        "owner": owner_subject,
        **parameters,
        "paired_at": now,
    })
    return {
        "state": cfg["state"],
        "owner": owner_subject,
        "parameters": parameters,
        "owner_proof": owner_proof,
    }


def config() -> dict:
    return device_config.load()


def factory_reset() -> dict:
    return device_config.factory_reset()
