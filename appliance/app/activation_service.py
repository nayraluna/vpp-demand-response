import base64
import datetime
import re
import sys
import threading
from pathlib import Path

import jwt  # PyJWT
import requests
from cryptography import x509

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import hsm  # noqa: E402
import vtn_client  # noqa: E402

from . import config as device_config  # noqa: E402
from .pairing_service import _issued_under_root, _within_validity  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from pki import chain as pki_chain  # noqa: E402
from pki import jws as pki_jws  # noqa: E402

SLOT_MINUTES = 30
SLOTS_PER_DAY = 24 * 60 // SLOT_MINUTES
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

DEFAULT_POLL_SECONDS = 60

# The poll loop and the HTTP handlers share config.json, one lock serialises every cycle.
_lock = threading.Lock()


class NotConfigured(Exception):
    """The appliance is still in pairing mode."""


def _adopt_list(der_b64: str, signer: x509.Certificate, cfg: dict, prefix: str) -> dict:
    """Adopt one X.509 CRL the VTN relays, verified against the CA that must have signed it.
    The CRL number must not go backwards, or a VPP could serve an older list to hide a revocation."""
    try:
        crl = x509.load_der_x509_crl(base64.b64decode(der_b64))
    except Exception as e:
        return {"status": "refused", "reason": f"revocation list is malformed: {e}"}
    if crl.issuer != signer.subject or not crl.is_signature_valid(signer.public_key()):
        return {"status": "refused", "reason": "revocation list not signed by the CA"}
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return {"status": "refused", "reason": "revocation list carries no CRL number"}
    if crl.next_update_utc is None:
        return {"status": "refused", "reason": "revocation list carries no nextUpdate"}
    stored = cfg.get(f"{prefix}_number") or 0
    if number < stored:
        return {"status": "refused",
                "reason": f"stale revocation list {number} (ours is {stored}): "
                          "an older list cannot replace a newer one"}

    # An equal number still refreshes nextUpdate: the CA re-signs the same list with a new window.
    cfg[f"{prefix}_number"] = number
    cfg[f"{prefix}_next_update"] = crl.next_update_utc.isoformat()
    cfg[f"{prefix}_revoked"] = [format(r.serial_number, "x") for r in crl]
    return {"status": "current" if number == stored else "stored",
            "crl_number": number, "revoked": len(cfg[f"{prefix}_revoked"])}


def _adopt_crls(crls: dict, cfg: dict) -> dict:
    """The appliance needs two lists: the platform CA's, for its owner, and the root's, for the
    platform CA itself. Each is verified against the certificate that must have signed it."""
    out = {}
    issuers = hsm.known_issuers()
    if crls.get("root"):
        out["root"] = _adopt_list(crls["root"], hsm.trust_anchor(), cfg, "arl")
    if crls.get("platform") and issuers:
        out["platform"] = _adopt_list(crls["platform"], issuers[0], cfg, "crl")
    return out


def _vtn_refusal(cfg: dict, peer: x509.Certificate) -> str | None:
    """TLS verified the VTN's chain. The appliance adds what TLS does not know: that the peer is the
    VPP it was paired with, and that the lists it holds do not name that certificate or its issuer."""
    try:
        paired = x509.load_pem_x509_certificate(Path(cfg["vpp_cert_file"]).read_bytes())
        if peer.subject != paired.subject:
            return "the VTN is not the VPP this appliance was paired with"
    except Exception as e:
        return f"paired VPP certificate unavailable: {e}"
    if format(peer.serial_number, "x") in (cfg.get("crl_revoked") or []):
        return "the VTN's certificate is revoked"
    if _issuing_ca_revoked(cfg):
        return "the issuing CA of the VTN's certificate is revoked"
    return None


def _vtn_serial_refused(cfg: dict) -> str | None:
    """Whether the VTN certificate seen on the last poll is now listed, for exchanges the appliance opens blind."""
    if cfg.get("vtn_serial") and cfg["vtn_serial"] in (cfg.get("crl_revoked") or []):
        return "the VTN's certificate is revoked"
    if _issuing_ca_revoked(cfg):
        return "the issuing CA of the VTN's certificate is revoked"
    return None


def _issuing_ca_revoked(cfg: dict) -> bool:
    """Whether the root's list names the platform issuing CA the appliance trusts for its owner."""
    issuers = hsm.known_issuers()
    return bool(issuers) and format(issuers[0].serial_number, "x") in (cfg.get("arl_revoked") or [])


def _adopt_calendar(jws_token: str, cfg: dict) -> dict:
    """Adopt the owner-signed calendar the VTN relays: only the owner's signature is
    trusted and the version must increase, so the VPP can neither alter nor roll it back."""
    try:
        certs = pki_chain.x5c_chain(jwt.get_unverified_header(jws_token))
        owner = certs[0]
        payload = pki_jws.decode_with(jws_token, owner, typ=pki_jws.TYP_AVAILABILITY)
    except Exception as e:
        return {"status": "refused",
                "reason": f"unsigned or malformed calendar: {e}"}

    # The signer must chain to the factory root. Matching the owner's name alone would let
    # anyone, the VPP included, mint a self-signed certificate with that subject.
    try:
        issuer = _issued_under_root(owner, certs[1:])
    except Exception as e:
        return {"status": "refused", "reason": f"factory root unavailable: {e}"}
    if issuer is None:
        return {"status": "refused",
                "reason": "calendar signer not certified by the CA"
                          if _within_validity(owner) else
                          "calendar signer certificate expired or not yet valid"}

    # A withdrawn signer still verifies, the lists adopted earlier in this poll decide.
    if format(owner.serial_number, "x") in (cfg.get("crl_revoked") or []) or _issuing_ca_revoked(cfg):
        return {"status": "refused",
                "reason": "calendar signer certificate is revoked"}

    if owner.subject.rfc4514_string() != cfg["owner"]:
        return {"status": "refused",
                "reason": "calendar not signed by the owner of this appliance"}

    # Remember the current serial: after a renewal the old one lands in the CRL as superseded.
    cfg["owner_serial"] = format(owner.serial_number, "x")

    version = payload.get("version")
    stored = cfg.get("availability_version") or 0
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        return {"status": "refused",
                "reason": "calendar carries no valid version"}
    if version == stored:
        return {"status": "current", "version": version}
    if version < stored:
        return {"status": "refused",
                "reason": f"stale calendar version {version} (ours is {stored}): "
                          "an older calendar cannot replace a newer one"}

    slots = payload.get("slots")
    if not isinstance(slots, dict) or set(slots) != set(DAYS):
        return {"status": "refused",
                "reason": "calendar must have exactly the seven weekdays"}
    for day, bitmap in slots.items():
        if not isinstance(bitmap, str) or len(bitmap) != SLOTS_PER_DAY \
                or set(bitmap) - {"0", "1"}:
            return {"status": "refused",
                    "reason": f"{day}: expected {SLOTS_PER_DAY} bits of 0/1"}

    cfg["availability"] = slots
    cfg["availability_version"] = version
    return {"status": "stored", "version": version,
            "declared_slots": sum(b.count("1") for b in slots.values())}


def _slot_label(index: int) -> str:
    minutes = index * SLOT_MINUTES
    return f"{minutes // 60:02d}:{minutes % 60:02d}"


def _check(activation: dict, cfg: dict, now: datetime.datetime) -> str | None:
    """Return the reason to refuse this activation, or None to accept it."""
    if activation["activation_id"] in cfg["processed"]:
        return "activation already processed (replay)"

    # Fail closed: without a revocation list still inside its window the appliance does not act.
    next_update = cfg.get("crl_next_update")
    if not next_update:
        return "no revocation list adopted yet"
    if now > datetime.datetime.fromisoformat(next_update):
        return f"revocation list expired at {next_update}, refusing to act"
    if cfg.get("owner_serial") and cfg["owner_serial"] in (cfg.get("crl_revoked") or []):
        return "owner certificate is revoked"
    if _issuing_ca_revoked(cfg):
        return "the issuing CA of the owner's certificate is revoked"

    day, start, end = activation["day"], activation["slot_start"], activation["slot_end"]
    if day not in DAYS or not (0 <= start < end <= SLOTS_PER_DAY):
        return "malformed interval"

    calendar = cfg.get("availability")
    if not calendar:
        return "no availability declared by the owner"
    if not all(c == "1" for c in calendar.get(day, "")[start:end]):
        return "interval outside the availability declared by the owner"

    # Only inside the activated window (UTC): a late or early delivery is refused, never run at another time.
    today = DAYS[now.weekday()]
    if day != today:
        return f"activation is for {day}; today is {today}"
    now_slot = now.hour * 2 + now.minute // SLOT_MINUTES
    if now_slot < start:
        return (f"activation window has not started yet "
                f"(starts at {_slot_label(start)} UTC)")
    if now_slot >= end:
        return (f"activation window has already elapsed "
                f"(ended at {_slot_label(end)} UTC)")
    # A weekday window repeats every week, so the absolute expiry is what refuses an old
    # activation replayed on the same weekday, and what lets its id be forgotten.
    expires = activation.get("ends_at")
    if not expires:
        return "activation carries no expiry"
    if now >= datetime.datetime.fromisoformat(expires):
        return f"activation expired at {expires}"

    duration = (end - start) * SLOT_MINUTES
    if duration > cfg["max"]:
        return f"interval of {duration} min exceeds our maximum ({cfg['max']} min)"

    last = cfg.get("last_activation")
    if last and last.get("ends_at"):
        elapsed = (now - datetime.datetime.fromisoformat(last["ends_at"])).total_seconds() / 60
        if elapsed < cfg["rec"]:
            return f"still recovering ({int(cfg['rec'] - elapsed)} min left)"
    return None


def _prune_processed(processed, now: datetime.datetime) -> dict:
    """Forget the ids whose activation has expired: _check refuses them anyway."""
    if isinstance(processed, list):
        return {}  # the old list form held no expiry, and every entry in it is long expired
    return {aid: expires for aid, expires in (processed or {}).items()
            if datetime.datetime.fromisoformat(expires) > now}


def _ven_identity() -> tuple[str, str]:
    return (str(Path(hsm.CERTS_DIR) / "VEN.crt"),
            str(Path(hsm.CERTS_DIR) / "VEN.key"))


def _ensure_registered(cfg: dict) -> None:
    """Register with the VTN (OpenADR EiRegisterParty) once, idempotent at the VTN."""
    if cfg.get("registration"):
        return
    cn = next((p.split("=", 1)[1] for p in hsm.subject().split(",")
               if p.strip().startswith("CN=")), hsm.subject())
    response = vtn_client.register(
        cfg["vpp_mtls_url"], str(hsm.CA_FILE), *_ven_identity(),
        ven_name=cn,
        profile={"P": hsm.nominal_power(), "max": cfg["max"], "rec": cfg["rec"]},
    )
    requested = re.fullmatch(r"PT(\d+)S",
                             response.get("oadrRequestedOadrPollFreq") or "")
    cfg["registration"] = {
        "ven_id": response.get("venID"),
        "registration_id": response.get("registrationID"),
        "poll_seconds": int(requested.group(1)) if requested
        else DEFAULT_POLL_SECONDS,
    }
    device_config.save(cfg)


def poll_seconds() -> int:
    registration = device_config.load().get("registration") or {}
    return registration.get("poll_seconds") or DEFAULT_POLL_SECONDS


def poll_and_process() -> dict:
    with _lock:
        return _poll_and_process()


def _poll_and_process() -> dict:
    cfg = device_config.load()
    if cfg["state"] != 1:
        raise NotConfigured("appliance is not paired yet")

    def refused(reason: str, crls: dict) -> dict:
        device_config.save(cfg)
        return {"polled": 0, "crl": crls.get("platform"), "arl": crls.get("root"), "calendar": None,
                "executed": [], "refused": [], "status": "refused", "reason": reason}

    status, body, peer = vtn_client.poll(cfg["vpp_mtls_url"], str(hsm.CA_FILE), *_ven_identity())
    if not cfg.get("registration"):
        # First contact after pairing: judge the channel with the lists held so far, register
        # through it (idempotent at the VTN), and pull again if the VTN did not know us yet.
        reason = _vtn_refusal(cfg, peer)
        if reason:
            return refused(reason, {})
        _ensure_registered(cfg)
        if status == 403:
            status, body, peer = vtn_client.poll(cfg["vpp_mtls_url"], str(hsm.CA_FILE), *_ven_identity())
    if status != 200:
        raise requests.HTTPError(f"{status} from the VTN: {body}")

    # Revocation lists first: the calendar adopted next is judged against them.
    crls = _adopt_crls(body.get("crls") or {}, cfg)
    crl = crls.get("platform")

    # With the lists current, the channel that delivered this body is judged: a revoked or
    # unexpected VTN delivers nothing, and the serial is kept for the exchanges the appliance
    # opens without first reading a list.
    cfg["vtn_serial"] = format(peer.serial_number, "x")
    reason = _vtn_refusal(cfg, peer)
    if reason:
        return refused(reason, crls)

    # Calendar before activations, so this pull's activations are judged against the latest one.
    calendar = None
    if body.get("calendar"):
        calendar = _adopt_calendar(body["calendar"], cfg)
    activations = body.get("activations", [])

    now = datetime.datetime.now(datetime.timezone.utc)
    cfg["processed"] = _prune_processed(cfg.get("processed"), now)
    executed, refused = [], []
    for activation in activations:
        reason = _check(activation, cfg, now)
        # Marked processed even when refused: never accepted twice while it can still be valid.
        cfg["processed"][activation["activation_id"]] = activation.get("ends_at") or now.isoformat()
        if reason:
            refused.append({"activation_id": activation["activation_id"],
                            "reason": reason})
            continue

        # Runs until the end of the activated window, never past what the owner authorised.
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        window_end = midnight + datetime.timedelta(
            minutes=activation["slot_end"] * SLOT_MINUTES)
        record = {
            "activation_id": activation["activation_id"],
            "action": activation["action"],
            "day": activation["day"],
            "slot_start": activation["slot_start"],
            "slot_end": activation["slot_end"],
            "executed_at": now.isoformat(),
            "ends_at": window_end.isoformat(),
            # Emulated: a real appliance measures this.
            "reduction_pct": 100 if activation["action"] == "shutdown" else 50,
        }
        cfg["last_activation"] = record
        cfg["history"].append(record)
        executed.append(record)

    device_config.save(cfg)
    return {"polled": len(activations), "crl": crl, "arl": crls.get("root"), "calendar": calendar,
            "executed": executed, "refused": refused}


def run_cycle() -> dict | None:
    """One tick of the periodic loop, None while unpaired."""
    if device_config.load()["state"] != 1:
        return None
    outcome = poll_and_process()
    # Nothing goes to a VTN the poll just refused.
    evidence = submit_evidence() if outcome.get("status") != "refused" else {"submitted": [], "rejected": []}
    return {**outcome, "evidence": evidence}


def submit_evidence() -> dict:
    """Submit evidence for every curtailment not yet reported, signed in the HSM so only this appliance can produce it."""
    with _lock:
        return _submit_evidence()


def _submit_evidence() -> dict:
    cfg = device_config.load()
    if cfg["state"] != 1:
        raise NotConfigured("appliance is not paired yet")
    reason = _vtn_serial_refused(cfg)
    if reason:
        return {"submitted": [], "rejected": [], "status": "refused", "reason": reason}

    submitted, rejected = [], []
    for record in cfg.get("history", []):
        if record["activation_id"] in cfg.get("submitted", []):
            continue
        executed = datetime.datetime.fromisoformat(record["executed_at"])
        proof = hsm.sign_jws({
            "activation_id": record["activation_id"],
            "ven": hsm.subject(),
            "date": executed.date().isoformat(),
            "time": executed.strftime("%H:%M"),
            "executed_at": record["executed_at"],
            "reduction_pct": record["reduction_pct"],
        }, typ=pki_jws.TYP_EVIDENCE)

        result = vtn_client.submit_evidence(
            cfg["vpp_mtls_url"], str(hsm.CA_FILE), *_ven_identity(), proof)

        if result["status_code"] == 200:
            cfg.setdefault("submitted", []).append(record["activation_id"])
            submitted.append({"activation_id": record["activation_id"],
                              "reduction_pct": record["reduction_pct"]})
        else:
            rejected.append({"activation_id": record["activation_id"],
                             "status": result["status_code"],
                             "error": result["body"].get("error")})
    device_config.save(cfg)
    return {"submitted": submitted, "rejected": rejected}


def status() -> dict:
    cfg = device_config.load()
    return {"state": cfg["state"], "owner": cfg["owner"],
            "owner_serial": cfg.get("owner_serial"),
            "registration": cfg.get("registration"),
            "availability_declared": cfg.get("availability") is not None,
            "availability_version": cfg.get("availability_version") or 0,
            "crl_number": cfg.get("crl_number") or 0,
            "crl_next_update": cfg.get("crl_next_update"),
            "crl_revoked": len(cfg.get("crl_revoked") or []),
            "arl_number": cfg.get("arl_number") or 0,
            "last_activation": cfg.get("last_activation"),
            "executed_count": len(cfg.get("history", []))}
