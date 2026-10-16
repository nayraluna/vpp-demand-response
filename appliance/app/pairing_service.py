import datetime
import sys
from pathlib import Path

import jwt  # PyJWT
from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
import hsm  # noqa: E402
from pki import chain as pki_chain  # noqa: E402
from pki import jws as pki_jws  # noqa: E402

from . import config as device_config  # noqa: E402


class InvalidBundle(Exception):
    """The onboarding bundle is malformed, unsigned, or not owned by an RA user."""


class AlreadyPaired(Exception):
    """Already in state 1, a factory reset is required first."""


def _issued_under_root(cert: x509.Certificate, carried: list[x509.Certificate] = ()) -> x509.Certificate | None:
    """The issuing CA under which `cert` chains to the factory root, or None. Fails closed on any error."""
    return pki_chain.issued_under(cert, list(carried) + hsm.known_issuers(), hsm.trust_anchor())


def _within_validity(cert: x509.Certificate) -> bool:
    """Expired certificates drop off the CRL, so this keeps a withdrawn credential refused past its expiry."""
    return pki_chain.within_validity(cert)


def pair(jws_token: str) -> dict:
    cfg = device_config.load()
    if cfg["state"] != 0:
        raise AlreadyPaired(f"appliance already paired with {cfg['owner']}")

    try:
        header = jwt.get_unverified_header(jws_token)
    except Exception as e:
        raise InvalidBundle(f"not a JWS: {e}")
    certs = pki_chain.x5c_chain(header)
    if not certs:
        raise InvalidBundle("bundle has no owner certificate (x5c)")
    owner = certs[0]
    try:
        # A bundle is a one-shot request: typed, short-lived, and addressed to this appliance,
        # so a captured one cannot be replayed to a reset device or carried to another.
        payload = pki_jws.decode_with(jws_token, owner, typ=pki_jws.TYP_PAIRING, require_exp=True)
    except pki_jws.WrongType as e:
        raise InvalidBundle(str(e))
    except Exception as e:
        raise InvalidBundle(f"owner signature invalid or bundle expired: {e}")
    if payload.get("ven") != hsm.subject():
        raise InvalidBundle("bundle is not addressed to this appliance")

    # Any cert_ra in the bundle is ignored: a root received over the channel it protects
    # would let anyone on the LAN enrol an unpaired appliance into a VPP of their own.
    try:
        vpp_chain = pki_chain.load_pem_chain(payload["cert_vpp"])
        cert_vpp = vpp_chain[0]
    except Exception as e:
        raise InvalidBundle(f"missing/invalid VPP certificate in bundle: {e}")
    # Validity is part of the chain check: an expired signer has no path to the root.
    if _issued_under_root(owner, certs[1:]) is None:
        raise InvalidBundle("owner certificate not issued under the platform root"
                            if _within_validity(owner) else "owner certificate expired or not yet valid")
    if _issued_under_root(cert_vpp, vpp_chain[1:]) is None:
        raise InvalidBundle("VPP certificate not issued under the platform root"
                            if _within_validity(cert_vpp) else "VPP certificate expired or not yet valid")

    owner_subject = owner.subject.rfc4514_string()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    here = Path(__file__).resolve().parent.parent
    vpp_file = here / "trust_vpp.pem"
    vpp_file.write_text(payload["cert_vpp"])
    cfg.update({
        "state": 1,
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
    # Ten minutes: the application forwards it at once, and a captured proof must not bind later.
    owner_proof = hsm.sign_jws({
        "ven": hsm.subject(),
        "owner": owner_subject,
        **parameters,
        "paired_at": now,
    }, ttl_seconds=600)
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
