import base64
import datetime
import os
import sys
import threading
import time
from pathlib import Path

import requests
from cryptography import x509

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import chain as pki_chain  # noqa: E402

from . import db  # noqa: E402

CERTS_DIR = ROOT_DIR / "certs"
ROOT_CERT_FILE = CERTS_DIR / "CA.crt"
ISSUING_CERT_FILES = {"platform": CERTS_DIR / "platform-ca.crt", "device": CERTS_DIR / "device-ca.crt"}

# Plain HTTP on purpose: a CRL is checked by its signature, not by the channel.
CRL_BASE = os.environ.get("TFG_CRL_FETCH_BASE", "http://127.0.0.1:8083/ra/crl")
# Seconds a cached list may age before refresh; run_all.ps1 sets 0 so gates see revocations at once.
MAX_AGE = float(os.environ.get("TFG_CRL_MAX_AGE", "300"))
# Three lists: one per issuing CA, and the root's list of revoked issuing CAs.
ISSUERS = ("platform", "device", "root")

_lock = threading.Lock()
_crls: dict[str, x509.CertificateRevocationList] = {}
_fetched_at = 0.0
_signers: dict[str, x509.Certificate] = {}


class Unavailable(Exception):
    """No current list is held, so revocation status cannot be decided."""


def _signer(issuer: str) -> x509.Certificate:
    """Who must have signed each list: the issuing CA its own, the root the issuing CAs'."""
    if not _signers:
        root = x509.load_pem_x509_certificate(ROOT_CERT_FILE.read_bytes())
        _signers["root"] = root
        for name, f in ISSUING_CERT_FILES.items():
            cert = x509.load_pem_x509_certificate(f.read_bytes())
            # An issuing certificate the root did not sign must never vouch for a list.
            cert.verify_directly_issued_by(root)
            _signers[name] = cert
    return _signers[issuer]


def load(issuer: str, der_b64: str) -> x509.CertificateRevocationList:
    """Parse and verify a list against its signer: signature, issuer name, and a CRL number."""
    crl = x509.load_der_x509_crl(base64.b64decode(der_b64))
    signer = _signer(issuer)
    if crl.issuer != signer.subject or not crl.is_signature_valid(signer.public_key()):
        raise ValueError(f"{issuer} revocation list not signed by its CA")
    number(crl)
    return crl


def number(crl: x509.CertificateRevocationList) -> int:
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def _fetch(issuer: str) -> tuple[str, x509.CertificateRevocationList]:
    r = requests.get(f"{CRL_BASE}/{issuer}", timeout=5)
    r.raise_for_status()
    der_b64 = base64.b64encode(r.content).decode()
    return der_b64, load(issuer, der_b64)


def _discard_relay_copies_if_foreign() -> None:
    """After a root regeneration the stored lists no longer chain and their numbers would block newer ones."""
    for issuer in ISSUERS:
        stored = db.get_crl(issuer)
        if stored is None:
            continue
        try:
            load(issuer, stored)
        except Exception:
            db.clear_crl(issuer)


def _expired(crl: x509.CertificateRevocationList) -> bool:
    until = crl.next_update_utc
    return until is None or datetime.datetime.now(datetime.timezone.utc) > until


def current() -> dict[str, x509.CertificateRevocationList]:
    """The verified lists, refreshed after MAX_AGE; refuses past nextUpdate so callers fail closed."""
    global _fetched_at
    with _lock:
        if not _crls:
            _discard_relay_copies_if_foreign()
        if len(_crls) < len(ISSUERS) or time.monotonic() - _fetched_at > MAX_AGE:
            for issuer in ISSUERS:
                try:
                    der_b64, fresh = _fetch(issuer)
                    # A lower CRL number than the one held means a replay: keep ours.
                    if issuer not in _crls or number(fresh) >= number(_crls[issuer]):
                        _crls[issuer] = fresh
                        # Kept verbatim: the appliance verifies these same signed lists itself.
                        db.store_crl(issuer, der_b64, number(fresh),
                                     datetime.datetime.now(datetime.timezone.utc).isoformat())
                except Exception:
                    if issuer not in _crls:
                        raise Unavailable(f"{issuer} revocation list could not be fetched from the CA")
            _fetched_at = time.monotonic()
        for issuer, crl in _crls.items():
            if _expired(crl):
                raise Unavailable(f"{issuer} revocation list expired at {crl.next_update_utc}"
                                  " and the CA has not published a fresh one")
        return dict(_crls)


def is_revoked(cert: x509.Certificate, issuer: x509.Certificate | None = None) -> bool:
    """Revoked if its serial is on its issuer's list, or its issuing CA is on the root's.

    `issuer` is the issuing CA the chain check found; without it, the name on the certificate decides.
    """
    lists = current()
    issuer_name = next((n for n, c in _signers.items() if n != "root"
                        and c.subject == (issuer.subject if issuer else cert.issuer)), None)
    if issuer_name is None:
        return True  # an issuer the VPP does not know cannot vouch for anything
    issuing_cert = _signers[issuer_name]
    if lists["root"].get_revoked_certificate_by_serial_number(issuing_cert.serial_number) is not None:
        return True
    return lists[issuer_name].get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def relay_copies() -> dict[str, str | None]:
    """The lists as last fetched, verbatim, for the appliance to verify itself."""
    return {issuer: db.get_crl(issuer) for issuer in ISSUERS}
