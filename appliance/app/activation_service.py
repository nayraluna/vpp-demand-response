import base64
import datetime
import re
import sys
import threading
from pathlib import Path

import jwt  # PyJWT
from cryptography import x509
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import hsm  # noqa: E402
import vtn_client  # noqa: E402

from . import config as device_config  # noqa: E402
from .pairing_service import _issued_by  # noqa: E402

SLOT_MINUTES = 30
SLOTS_PER_DAY = 48
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

DEFAULT_POLL_SECONDS = 60

# The periodic poll loop and the HTTP handlers run in different threads but
# share config.json (read-modify-write); one lock serialises every cycle.
_lock = threading.Lock()


class NotConfigured(Exception):
    """The appliance is still in pairing mode."""


def _adopt_calendar(jws_token: str, cfg: dict) -> dict:
    """Verify and adopt the owner-signed calendar relayed by the VTN.

    The VPP relays the calendar verbatim inside the poll response; the
    appliance trusts only the owner's signature on it -- made by a key whose
    certificate chains to the CA root recorded at pairing -- and accepts only
    a version strictly greater than the one it holds. A misbehaving VPP can
    therefore neither alter the calendar (it cannot produce the owner's
    signature) nor roll it back to an older, more permissive one (the
    monotonic version refuses the replay). The caller persists cfg.
    """
    try:
        header = jwt.get_unverified_header(jws_token)
        owner = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
        owner_pub = owner.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        # ES256 = Android Keystore EC credential; RS256 = JVM/software keys.
        payload = jwt.decode(jws_token, owner_pub, algorithms=["RS256", "ES256"])
    except Exception as e:
        return {"status": "refused",
                "reason": f"unsigned or malformed calendar: {e}"}

    # The signer's certificate must chain to the CA root recorded at pairing.
    # Matching the owner's NAME is not enough: without this check anyone -- the
    # VPP included -- could mint a self-signed certificate bearing the owner's
    # subject and have a forged or rolled-back calendar accepted.
    try:
        ra_cert = x509.load_pem_x509_certificate(
            Path(cfg["ra_cert_file"]).read_bytes())
    except Exception as e:
        return {"status": "refused",
                "reason": f"trust anchor from pairing unavailable: {e}"}
    if not _issued_by(owner, ra_cert):
        return {"status": "refused",
                "reason": "calendar signer not certified by the CA"}

    # Only the owner recorded at pairing may set this appliance's availability.
    if owner.subject.rfc4514_string() != cfg["owner"]:
        return {"status": "refused",
                "reason": "calendar not signed by the owner of this appliance"}

    version = payload.get("version")
    stored = cfg.get("availability_version") or 0
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        return {"status": "refused",
                "reason": "calendar carries no valid version"}
    if version == stored:
        # Steady state: the VTN re-delivers the current calendar every poll.
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
    if activation["nonce"] in cfg["seen_nonces"]:
        return "nonce already seen (replay)"

    day, start, end = activation["day"], activation["slot_start"], activation["slot_end"]
    if day not in DAYS or not (0 <= start < end <= SLOTS_PER_DAY):
        return "malformed interval"

    calendar = cfg.get("availability")
    if not calendar:
        return "no availability declared by the owner"
    if not all(c == "1" for c in calendar.get(day, "")[start:end]):
        return "interval outside the availability declared by the owner"

    # The curtailment must happen WHEN the activation says: the wall clock
    # (UTC, as everywhere in the platform) must be inside the activated day and
    # slot window. A delivered-late or premature activation is refused, never
    # executed at some other time than its owner-visible window.
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

    duration = (end - start) * SLOT_MINUTES
    if duration > cfg["max"]:
        return f"interval of {duration} min exceeds our maximum ({cfg['max']} min)"

    last = cfg.get("last_activation")
    if last and last.get("ends_at"):
        elapsed = (now - datetime.datetime.fromisoformat(last["ends_at"])).total_seconds() / 60
        if elapsed < cfg["rec"]:
            return f"still recovering ({int(cfg['rec'] - elapsed)} min left)"
    return None


def _ven_identity() -> tuple[str, str]:
    return (str(Path(hsm.CERTS_DIR) / "VEN.crt"),
            str(Path(hsm.CERTS_DIR) / "VEN.key"))


def _ensure_registered(cfg: dict) -> None:
    """Register with the VTN (OpenADR EiRegisterParty) if not done yet.

    This is the appliance's own outbound completion of the registration phase:
    no external party triggers it. Idempotent at the VTN, so a lost local
    config simply re-obtains the same registration.
    """
    if cfg.get("registration"):
        return
    cn = next((p.split("=", 1)[1] for p in hsm.subject().split(",")
               if p.strip().startswith("CN=")), hsm.subject())
    response = vtn_client.register(
        cfg["vpp_mtls_url"], cfg["ra_cert_file"], *_ven_identity(),
        ven_name=cn,
        profile={"P": hsm.nominal_power(), "max": cfg["max"], "rec": cfg["rec"]},
    )
    requested = re.fullmatch(r"PT(\d+)S",
                             response.get("oadrRequestedOadrPollFreq") or "")
    cfg["registration"] = {
        "ven_id": response.get("venID"),
        "registration_id": response.get("registrationID"),
        # The VTN states how often it wants to be polled; honour it.
        "poll_seconds": int(requested.group(1)) if requested
        else DEFAULT_POLL_SECONDS,
    }
    device_config.save(cfg)


def poll_seconds() -> int:
    """The polling period requested by the VTN at registration (with default)."""
    registration = device_config.load().get("registration") or {}
    return registration.get("poll_seconds") or DEFAULT_POLL_SECONDS


def poll_and_process() -> dict:
    """Poll the VPP and act on whatever it has for us."""
    with _lock:
        return _poll_and_process()


def _poll_and_process() -> dict:
    cfg = device_config.load()
    if cfg["state"] != 1:
        raise NotConfigured("appliance is not paired yet")

    # Complete the registration phase before the first pull, autonomously.
    _ensure_registered(cfg)

    body = vtn_client.poll(
        cfg["vpp_mtls_url"], cfg["ra_cert_file"], *_ven_identity(),
    )

    # The owner-signed calendar rides in the poll response; adopt it BEFORE
    # checking activations, so the same pull that delivers a new calendar has
    # its activations judged against the owner's latest declaration.
    calendar = None
    if body.get("calendar"):
        calendar = _adopt_calendar(body["calendar"], cfg)
    activations = body.get("activations", [])

    now = datetime.datetime.now(datetime.timezone.utc)
    executed, refused = [], []
    for activation in activations:
        reason = _check(activation, cfg, now)
        # Seen once, never accepted twice - even if we refuse it.
        cfg["processed"].append(activation["activation_id"])
        cfg["seen_nonces"].append(activation["nonce"])
        if reason:
            refused.append({"activation_id": activation["activation_id"],
                            "reason": reason})
            continue

        # The curtailment runs from now (we are inside the window, _check
        # guarantees it) until the END of the activated window - never past
        # what the owner-visible interval authorises. Recovery counts from
        # that same instant.
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        window_end = midnight + datetime.timedelta(
            minutes=activation["slot_end"] * SLOT_MINUTES)
        record = {
            "activation_id": activation["activation_id"],
            "action": activation["action"],
            "day": activation["day"],
            "slot_start": activation["slot_start"],
            "slot_end": activation["slot_end"],
            "nonce": activation["nonce"],
            "executed_at": now.isoformat(),
            "ends_at": window_end.isoformat(),
            # A real appliance measures this; the emulated one delivers what was
            # asked: a full shutdown is 100%, a reduction is 50% of nominal power.
            "reduction_pct": 100 if activation["action"] == "shutdown" else 50,
        }
        cfg["last_activation"] = record
        cfg["history"].append(record)
        executed.append(record)

    device_config.save(cfg)
    return {"polled": len(activations), "calendar": calendar,
            "executed": executed, "refused": refused}


def run_cycle() -> dict | None:
    """One tick of the periodic loop: register if needed, poll, act, testify.

    Returns None while the appliance is unpaired (nothing to do)."""
    if device_config.load()["state"] != 1:
        return None
    outcome = poll_and_process()
    evidence = submit_evidence()
    return {**outcome, "evidence": evidence}


def submit_evidence() -> dict:
    """Generate and submit evidence for every curtailment not yet reported.

    The message is signed INSIDE THE HSM with the certified appliance key, so
    only this appliance can produce valid evidence for its activations. It
    records when the curtailment ran, which activation it answers, and the
    reduction actually achieved as a percentage of the nominal power.
    """
    with _lock:
        return _submit_evidence()


def _submit_evidence() -> dict:
    cfg = device_config.load()
    if cfg["state"] != 1:
        raise NotConfigured("appliance is not paired yet")

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
            "nonce": record["nonce"],          # ties it to that activation
        }, typ="application/dr-evidence+json")

        result = vtn_client.submit_evidence(
            cfg["vpp_mtls_url"], cfg["ra_cert_file"], *_ven_identity(), proof)

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
            "registration": cfg.get("registration"),
            "availability_declared": cfg.get("availability") is not None,
            "availability_version": cfg.get("availability_version") or 0,
            "last_activation": cfg.get("last_activation"),
            "executed_count": len(cfg.get("history", []))}
