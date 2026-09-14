import base64
import datetime
import secrets
import time
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certs"
CA_FILE = str(CERTS / "CA.crt")
DB_FILE = ROOT / "vpp-server" / "vpp.db"
VPP, MTLS = "https://127.0.0.1:8080", "https://127.0.0.1:8443"
MAN, APP = "https://127.0.0.1:8081", "http://127.0.0.1:8082"

sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability as av  # noqa: E402

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="activation_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def reset_operational_state():
    """Test setup: drop activations/evidence left by an earlier run, so the
    appliance is not still inside a previous recovery window (which selection
    would correctly refuse) and the suite stays repeatable."""
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute("DELETE FROM evidence")
        c.execute("DELETE FROM activations")
        # A synthetic population left by the backoffice would absorb the
        # selection instead of the real appliance under test.
        c.execute("DELETE FROM availability WHERE ven_subject LIKE 'CN=syn-%'")
        c.execute("DELETE FROM appliances WHERE ven_subject LIKE 'CN=syn-%'")
        c.execute("DELETE FROM users WHERE subject LIKE 'CN=syn-user-%'")


def ra_identity(name: str, org_unit: str | None = None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, name)]
    if org_unit:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name(attrs)).sign(key, hashes.SHA256()))
    r = requests.post(f"{MAN}/ra/issue",
                      json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
                      verify=CA_FILE)
    if not r.ok:
        die(f"RA /ra/issue -> {r.status_code} {r.text}")
    cert_pem = r.json()["certificate"]
    requests.post(f"{VPP}/enroll", json={"certificate": cert_pem}, verify=CA_FILE)
    cf, kf = tmp / f"{name}.crt", tmp / f"{name}.key"
    cf.write_text(cert_pem)
    kf.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key, cert_pem, (str(cf), str(kf))


def sign_as(key, cert_pem: str, payload: dict, typ: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256",
                      headers={"x5c": [x5c], "typ": typ})


def onboard(key, cert_pem, client, calendar) -> str:
    """Pair, bind ownership, and declare the owner-signed calendar at the VPP.
    Neither the VEN registration nor the calendar delivery happen here: the
    appliance obtains both autonomously through its first outbound poll."""
    requests.post(f"{APP}/factory-reset")
    bundle = sign_as(key, cert_pem, {
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text()}, "application/pairing+json")
    proof = requests.post(f"{APP}/pair", json={"jws": bundle}).json()["owner_proof"]
    ven = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                        cert=client, verify=CA_FILE).json()["ven"]
    r = requests.post(
        f"{MTLS}/availability",
        json={"ven": ven,
              "jws": sign_as(key, cert_pem,
                             {"slots": calendar, "version": int(time.time() * 1000)},
                             "application/availability+json")},
        cert=client, verify=CA_FILE)
    if not r.ok:
        die(f"VPP /availability -> {r.status_code} {r.text}")
    return ven


def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def now_slot() -> int:
    now = now_utc()
    return now.hour * 2 + now.minute // 30


def current_window(slots: int = 2) -> dict:
    """A window covering *now* (UTC): activations meant to execute use it."""
    start = min(now_slot(), av.SLOTS_PER_DAY - slots)
    return {"day": av.DAYS[now_utc().weekday()], "slot_start": start,
            "slot_end": start + slots}


def hole_slots() -> tuple[int, int]:
    """A 2-slot interval ~12 h away from now: outside it, the calendar is 1."""
    start = min((now_slot() + 24) % av.SLOTS_PER_DAY, av.SLOTS_PER_DAY - 2)
    return start, start + 2


def open_calendar() -> dict:
    """Full availability except the hole, every day: isolates each appliance
    check (availability vs time window) from the hour at which the gate runs."""
    hole_start, hole_end = hole_slots()
    bitmap = "1" * hole_start + "0" * (hole_end - hole_start) \
        + "1" * (av.SLOTS_PER_DAY - hole_end)
    return {day: bitmap for day in av.DAYS}


def inject_activation(ven: str, act_id: str, day: str, start: int, end: int):
    """Write an activation straight into the VPP's queue (adversarial cases)."""
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute(
            """INSERT INTO activations(activation_id, ven_subject, day,
                   slot_start, slot_end, action, nonce, issued_at, ends_at,
                   delivered_at)
               VALUES(?,?,?,?,?,'reduce',?,'2026-01-01T00:00:00+00:00',NULL,NULL)""",
            (act_id, ven, day, start, end, secrets.token_hex(16)))


def main():
    try:
        reset_operational_state()
        calendar = open_calendar()
        ukey, ucert, uclient = ra_identity(f"user-{secrets.token_hex(3)}")
        ven = onboard(ukey, ucert, uclient, calendar)
        _k, _c, operator = ra_identity(f"dr-{secrets.token_hex(3)}", "role=operator")
        window = current_window()

        print("G0: the appliance registers itself with the VTN on first contact")
        r = requests.post(f"{APP}/poll")
        if not r.ok:
            die(f"first poll -> {r.status_code} {r.text}")
        st = requests.get(f"{APP}/status").json()
        registration = st.get("registration")
        ok(f"self-registered as {registration['ven_id']} "
           f"({registration['registration_id']}, polls every "
           f"{registration['poll_seconds']} s)") \
            if registration and registration.get("registration_id") \
            else die(f"appliance did not register itself: {registration}")
        ok("the owner-signed calendar arrived through the same outbound poll "
           f"(version {st['availability_version']})") \
            if st["availability_declared"] else die(f"calendar not adopted: {st}")

        print("G1: an infeasible request activates nobody")
        r = requests.post(f"{MTLS}/dr/activate",
                          json={"power_w": 999999, **window, "action": "reduce"},
                          cert=operator, verify=CA_FILE)
        ok(f"refused (409): {r.json()['reason']}") if r.status_code == 409 \
            else die(f"expected 409, got {r.status_code} {r.text}")
        before = sqlite3.connect(str(DB_FILE)).execute(
            "SELECT COUNT(*) FROM activations").fetchone()[0]

        print("G2: a feasible request issues an activation with id and nonce")
        r = requests.post(f"{MTLS}/dr/activate",
                          json={"power_w": 1000, **window, "action": "reduce"},
                          cert=operator, verify=CA_FILE)
        if r.status_code != 200:
            die(f"expected 200, got {r.status_code} {r.text}")
        issued = r.json()["activations"]
        act_id = issued[0]["activation_id"]
        ok(f"activation {act_id} issued for {r.json()['interval']}")
        row = sqlite3.connect(str(DB_FILE)).execute(
            "SELECT nonce, delivered_at FROM activations WHERE activation_id=?",
            (act_id,)).fetchone()
        ok(f"carries a 128-bit nonce ({row[0][:12]}...)") if len(row[0]) == 32 \
            else die(f"unexpected nonce {row[0]}")
        ok("not delivered yet (the appliance must come and fetch it)") \
            if row[1] is None else die("marked delivered before polling")
        after = sqlite3.connect(str(DB_FILE)).execute(
            "SELECT COUNT(*) FROM activations").fetchone()[0]
        ok("the infeasible request left no activation behind") \
            if after == before + len(issued) else die("unexpected activation count")

        print("G3: the appliance retrieves it by polling and curtails")
        r = requests.post(f"{APP}/poll")
        body = r.json()
        if not body["executed"]:
            die(f"appliance did not execute: {body}")
        done = body["executed"][0]
        ok(f"executed {done['action']} for activation {done['activation_id']} "
           f"({done['reduction_pct']}% reduction)") \
            if done["activation_id"] == act_id else die(f"unexpected {done}")
        st = requests.get(f"{APP}/status").json()
        ok(f"appliance records the curtailment (executed_count={st['executed_count']})") \
            if st["executed_count"] >= 1 else die("no record kept")

        print("G4: an activation is delivered once")
        body = requests.post(f"{APP}/poll").json()
        ok("polling again returns nothing new") if body["polled"] == 0 \
            else die(f"activation delivered twice: {body}")

        print("G5: a replayed activation is refused by the appliance")
        # Re-issue the very same activation straight into the VPP's queue.
        with sqlite3.connect(str(DB_FILE)) as c:
            c.execute("UPDATE activations SET delivered_at=NULL WHERE activation_id=?",
                      (act_id,))
        body = requests.post(f"{APP}/poll").json()
        ok(f"refused: {body['refused'][0]['reason']}") \
            if body["refused"] and "replay" in body["refused"][0]["reason"] \
            else die(f"replay not refused: {body}")

        print("G6: an activation outside the declared availability is refused")
        hole_start, hole_end = hole_slots()
        inject_activation(ven, "act-hole", current_window()["day"],
                          hole_start, hole_end)
        body = requests.post(f"{APP}/poll").json()
        reasons = [x["reason"] for x in body["refused"]]
        ok(f"refused: {reasons[0]}") \
            if any("outside the availability" in x for x in reasons) \
            else die(f"hole activation not refused: {body}")

        print("G7: an activation is executed WHEN it says, or not at all")
        # For another day of the week: must never run today.
        tomorrow = av.DAYS[(now_utc().weekday() + 1) % 7]
        inject_activation(ven, "act-tomorrow", tomorrow,
                          window["slot_start"], window["slot_end"])
        # For today, but a window that does not cover *now* (already elapsed,
        # or - within the first hour of the day - not started yet).
        slot = now_slot()
        off_start, off_end = (slot - 2, slot) if slot >= 2 else (slot + 4, slot + 6)
        inject_activation(ven, "act-offwindow", current_window()["day"],
                          off_start, off_end)
        body = requests.post(f"{APP}/poll").json()
        refused = {x["activation_id"]: x["reason"] for x in body["refused"]}
        ok(f"another day refused: {refused.get('act-tomorrow')}") \
            if "today is" in refused.get("act-tomorrow", "") \
            else die(f"tomorrow's activation not refused by day: {body}")
        ok(f"outside its slot window refused: {refused.get('act-offwindow')}") \
            if "window" in refused.get("act-offwindow", "") \
            else die(f"off-window activation not refused: {body}")
        st = requests.get(f"{APP}/status").json()
        ok("nothing was executed outside its window "
           f"(executed_count still {st['executed_count']})") \
            if st["executed_count"] == 1 else die(f"unexpected execution: {st}")

        print("G8: only a registered VEN may poll")
        _uk, _uc, stranger = ra_identity(f"user-{secrets.token_hex(3)}")
        r = requests.get(f"{MTLS}/openadr/poll", cert=stranger, verify=CA_FILE)
        ok("a non-VEN identity is refused (403)") if r.status_code == 403 \
            else die(f"expected 403, got {r.status_code}")

        print(f"\nACTIVATION (OPERATIONAL 3) COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
