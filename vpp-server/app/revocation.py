import datetime
import os
import threading
import time
from pathlib import Path

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import db

CERTS_DIR = Path(__file__).resolve().parent.parent.parent / "certs"
CA_CERT_FILE = CERTS_DIR / "CA.crt"

# Seconds a cached list may age before refresh; run_all.ps1 sets 0 so gates see revocations at once.
CA_URL = os.environ.get("TFG_CA_URL", "https://127.0.0.1:8081")
MAX_AGE = float(os.environ.get("TFG_CRL_MAX_AGE", "300"))

_lock = threading.Lock()
_crl: dict | None = None
_fetched_at = 0.0
_ca_public_pem: bytes | None = None


class Unavailable(Exception):
    """No current list is held, so revocation status cannot be decided."""


def _anchor() -> bytes:
    global _ca_public_pem
    if _ca_public_pem is None:
        cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
        _ca_public_pem = cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _ca_public_pem


def _fetch() -> tuple[str, dict]:
    r = requests.get(f"{CA_URL}/ra/crl", verify=str(CA_CERT_FILE), timeout=5)
    r.raise_for_status()
    token = r.json()["crl"]
    return token, jwt.decode(token, _anchor(), algorithms=["RS256"])


def _discard_relay_copy_if_foreign() -> None:
    """After a CA root regeneration the stored list no longer chains and its number would block newer ones."""
    stored = db.get_crl()
    if stored is None:
        return
    try:
        jwt.decode(stored, _anchor(), algorithms=["RS256"])
    except Exception:
        db.clear_crl()


def _expired(crl: dict) -> bool:
    try:
        until = datetime.datetime.fromisoformat(crl["next_update"])
    except Exception:
        return True
    return datetime.datetime.now(datetime.timezone.utc) > until


def current() -> dict:
    """The verified list, refreshed after MAX_AGE; refuses past next_update so callers fail closed."""
    global _crl, _fetched_at
    with _lock:
        if _crl is None:
            _discard_relay_copy_if_foreign()
        if _crl is None or time.monotonic() - _fetched_at > MAX_AGE:
            try:
                token, fresh = _fetch()
                # A lower crl_number than the one held means a replay: keep ours.
                if _crl is None or fresh["crl_number"] >= _crl["crl_number"]:
                    _crl = fresh
                    # Kept verbatim: the appliance verifies this same signed list itself.
                    db.store_crl(token, fresh["crl_number"],
                                 datetime.datetime.now(datetime.timezone.utc).isoformat())
            except Exception:
                if _crl is None:
                    raise Unavailable("revocation list could not be fetched from the CA")
            _fetched_at = time.monotonic()
        if _expired(_crl):
            raise Unavailable(f"revocation list expired at {_crl.get('next_update')}"
                              " and the CA has not published a fresh one")
        return _crl


def is_revoked(cert: x509.Certificate) -> bool:
    serial = format(cert.serial_number, "x")
    return any(entry["serial"] == serial for entry in current()["revoked"])
