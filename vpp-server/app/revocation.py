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

# Where the list comes from, and how old a cached copy may get before the next
# check refreshes it. run_all.ps1 sets the age to 0 so every gate sees a
# revocation the moment it happens. Interactive runs keep the default.
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
    # The CA signs the list with its own key, and CA.crt is already this
    # service's trust anchor, so the signature is checked straight against it.
    return token, jwt.decode(token, _anchor(), algorithms=["RS256"])


def _discard_relay_copy_if_foreign() -> None:
    """Once per process, before the first fetch. The relay copy only ever moves
    to a higher list number, which is right while the CA stays the same and
    wrong the moment the root is regenerated: the old list would then sit at a
    number the new CA takes months to reach, and the appliance would be handed
    a list that no longer chains. A copy that does not verify against the
    current root is not a list at all, so it is dropped."""
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
    """The verified list, refreshed once the cached copy is older than MAX_AGE.

    A refresh that fails keeps the last good copy, because a stale list is
    still a signed statement by the CA, but only for as long as the CA said
    it would stand. Past its next_update, or when no list was ever obtained,
    this refuses to answer and callers fail closed, the same rule the
    appliance applies to its own copy."""
    global _crl, _fetched_at
    with _lock:
        if _crl is None:
            _discard_relay_copy_if_foreign()
        if _crl is None or time.monotonic() - _fetched_at > MAX_AGE:
            try:
                token, fresh = _fetch()
                # The CA never goes backwards. If this copy is older than the
                # one we hold, something in between is replaying, keep ours.
                if _crl is None or fresh["crl_number"] >= _crl["crl_number"]:
                    _crl = fresh
                    # The appliance gets this same signed list in its poll and
                    # verifies it itself, so the relay copy is kept verbatim.
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
