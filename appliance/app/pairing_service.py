import base64
import datetime
import sys
from pathlib import Path

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import hsm  # noqa: E402

from . import config as device_config  # noqa: E402


class InvalidBundle(Exception):
    """The onboarding bundle is malformed, unsigned, or not owned by an RA user."""


class AlreadyPaired(Exception):
    """The appliance is already configured (state 1); a factory reset is required."""


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        issuer.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        # Fail closed: a bad signature, a foreign signature scheme, or a
        # malformed certificate all mean "not issued by this issuer".
        return False


def _within_validity(cert: x509.Certificate) -> bool:
    """The signature proves the CA issued it, not that it is still current.
    An expired certificate also leaves the revocation list, so this is what
    keeps a withdrawn credential refused after its own expiry date."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def pair(jws_token: str) -> dict:
    cfg = device_config.load()
    if cfg["state"] != 0:
        raise AlreadyPaired(f"appliance already paired with {cfg['owner']}")

    # 1. The owner certificate travels in the x5c header of the bundle.
    try:
        header = jwt.get_unverified_header(jws_token)
    except Exception as e:
        raise InvalidBundle(f"not a JWS: {e}")
    x5c = header.get("x5c")
    if not x5c:
        raise InvalidBundle("bundle has no owner certificate (x5c)")
    owner = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))

    # 2. Verify the owner's signature over the payload. Users sign ES256
    #    (Android Keystore EC credential) or RS256 (JVM tests, software keys);
    #    the key type in the x5c certificate must match the declared alg,
    #    which PyJWT enforces.
    owner_pub = owner.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        payload = jwt.decode(jws_token, owner_pub, algorithms=["RS256", "ES256"])
    except Exception as e:
        raise InvalidBundle(f"owner signature invalid: {e}")

    # 3. The owner and the VPP must both be certified by the root this device
    #    left the factory with. A `cert_ra` field in the bundle, if any, is
    #    ignored: a trust anchor received over the channel it is meant to
    #    protect would let anyone on the LAN enrol an unpaired appliance into a
    #    VPP of their own, with a root of their own.
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

    # 4. Store the configuration and leave pairing mode (state 0 -> 1). The
    # trust anchor for every later call to the VPP is the factory root itself.
    # The VPP certificate is kept because it was verified against that root.
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

    # 5. Report our capabilities and produce the owner proof, signed in the HSM.
    parameters = {
        "P": hsm.nominal_power(),   # certified by the CA in the cert
        "max": cfg["max"],          # device property, from the config file
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
