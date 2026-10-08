import base64
import datetime
import os
import threading
import time
from pathlib import Path

import requests
from cryptography import x509

from . import db

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
CA_CERT_FILE = CERTS_DIR / "CA.crt"

# Seconds a cached list may age before refresh; run_all.ps1 sets 0 so gates see revocations at once.
CA_URL = os.environ.get("TFG_CA_URL", "https://127.0.0.1:8081")
MAX_AGE = float(os.environ.get("TFG_CRL_MAX_AGE", "300"))

_lock = threading.Lock()
_crl: x509.CertificateRevocationList | None = None
_fetched_at = 0.0
_root: x509.Certificate | None = None


class Unavailable(Exception):
    """No current list is held, so revocation status cannot be decided."""


def _anchor() -> x509.Certificate:
    global _root
    if _root is None:
        _root = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    return _root


def load(der_b64: str) -> x509.CertificateRevocationList:
    """Parse and verify a relayed list against the root: signature, issuer, and a CRL number."""
    crl = x509.load_der_x509_crl(base64.b64decode(der_b64))
    root = _anchor()
    if crl.issuer != root.subject or not crl.is_signature_valid(root.public_key()):
        raise ValueError("revocation list not signed by the CA")
    number(crl)
    return crl


def number(crl: x509.CertificateRevocationList) -> int:
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def _fetch() -> tuple[str, x509.CertificateRevocationList]:
    r = requests.get(f"{CA_URL}/ra/crl", verify=str(CA_CERT_FILE), timeout=5)
    r.raise_for_status()
    der_b64 = base64.b64encode(r.content).decode()
    return der_b64, load(der_b64)


def _discard_relay_copy_if_foreign() -> None:
    """After a CA root regeneration the stored list no longer chains and its number would block newer ones."""
    stored = db.get_crl()
    if stored is None:
        return
    try:
        load(stored)
    except Exception:
        db.clear_crl()


def _expired(crl: x509.CertificateRevocationList) -> bool:
    until = crl.next_update_utc
    return until is None or datetime.datetime.now(datetime.timezone.utc) > until


def current() -> x509.CertificateRevocationList:
    """The verified list, refreshed after MAX_AGE; refuses past nextUpdate so callers fail closed."""
    global _crl, _fetched_at
    with _lock:
        if _crl is None:
            _discard_relay_copy_if_foreign()
        if _crl is None or time.monotonic() - _fetched_at > MAX_AGE:
            try:
                der_b64, fresh = _fetch()
                # A lower CRL number than the one held means a replay: keep ours.
                if _crl is None or number(fresh) >= number(_crl):
                    _crl = fresh
                    # Kept verbatim: the appliance verifies this same signed list itself.
                    db.store_crl(der_b64, number(fresh),
                                 datetime.datetime.now(datetime.timezone.utc).isoformat())
            except Exception:
                if _crl is None:
                    raise Unavailable("revocation list could not be fetched from the CA")
            _fetched_at = time.monotonic()
        if _expired(_crl):
            raise Unavailable(f"revocation list expired at {_crl.next_update_utc}"
                              " and the CA has not published a fresh one")
        return _crl


def is_revoked(cert: x509.Certificate) -> bool:
    return current().get_revoked_certificate_by_serial_number(cert.serial_number) is not None
