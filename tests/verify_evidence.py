import base64
import datetime
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
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
VEN_CLIENT = (str(CERTS / "VEN.crt"), str(CERTS / "VEN.key"))

sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability as av  # noqa: E402

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="evidence_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def reset_operational_state():
    """Test setup: drop activations/evidence left by an earlier run.

    Without this the appliance would still be inside the recovery window of a
    previous activation, and participant selection would (correctly) refuse to
    activate it - making the suite non-repeatable.
    """
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
    r = requests.post(f"{VPP}/enroll", json={"certificate": cert_pem}, verify=CA_FILE)
    if not r.ok:
        die(f"VPP /enroll -> {r.status_code} {r.text}")
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


def full_calendar() -> dict:
    """Full availability: this gate is about evidence, not the calendar."""
    return {day: "1" * av.SLOTS_PER_DAY for day in av.DAYS}


def current_window(slots: int = 4) -> dict:
    """A window covering *now* (UTC): the appliance only executes inside it."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start = min(now.hour * 2 + now.minute // 30, av.SLOTS_PER_DAY - slots)
    return {"day": av.DAYS[now.weekday()], "slot_start": start,
            "slot_end": start + slots}


def onboard(key, cert_pem, client, calendar) -> str:
    # Every step is checked: a silent failure here surfaces later as an empty
    # evidence submission whose real cause is impossible to reconstruct.
    r = requests.post(f"{APP}/factory-reset")
    if not r.ok:
        die(f"appliance /factory-reset -> {r.status_code} {r.text}")
    bundle = sign_as(key, cert_pem, {
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text()}, "application/pairing+json")
    r = requests.post(f"{APP}/pair", json={"jws": bundle})
    if not r.ok:
        die(f"appliance /pair -> {r.status_code} {r.text}")
    proof = r.json()["owner_proof"]
    r = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                      cert=client, verify=CA_FILE)
    if not r.ok:
        die(f"owner proof -> {r.status_code} {r.text}")
    ven = r.json()["ven"]
    # No VEN registration and no calendar delivery here: the appliance obtains
    # both autonomously through its first outbound poll.
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


def main():
    try:
        reset_operational_state()
        calendar = full_calendar()
        ukey, ucert, uclient = ra_identity(f"user-{secrets.token_hex(3)}")
        ven = onboard(ukey, ucert, uclient, calendar)
        _k, _c, operator = ra_identity(f"dr-{secrets.token_hex(3)}", "role=operator")

        # Activate for the window that covers *now* (2 h -> the 2.0 kWh below),
        # and let the appliance retrieve and execute it.
        r = requests.post(f"{MTLS}/dr/activate",
                          json={"power_w": 1000, **current_window(),
                                "action": "reduce"},
                          cert=operator, verify=CA_FILE)
        if r.status_code != 200:
            die(f"VPP /dr/activate -> {r.status_code} {r.text}")
        act_id = r.json()["activations"][0]["activation_id"]
        r = requests.post(f"{APP}/poll")
        if not r.ok:
            die(f"appliance /poll -> {r.status_code} {r.text}")
        poll = r.json()

        print("G1: the appliance signs evidence in its HSM and the VPP verifies it")
        r = requests.post(f"{APP}/evidence")
        body = r.json()
        if not body["submitted"]:
            # The poll outcome carries the refusal reason (or the calendar
            # rejection) that explains an empty submission.
            die(f"nothing submitted: {body} (poll outcome: {poll})")
        ok(f"evidence accepted for {body['submitted'][0]['activation_id']} "
           f"({body['submitted'][0]['reduction_pct']}% reduction)") \
            if body["submitted"][0]["activation_id"] == act_id \
            else die(f"unexpected {body}")

        print("G2: the signature itself is stored as the auditable record")
        row = sqlite3.connect(str(DB_FILE)).execute(
            """SELECT ven_subject, reduction_pct, jws, verified_at
               FROM evidence WHERE activation_id=?""", (act_id,)).fetchone()
        if not row:
            die("evidence not stored")
        ok(f"stored for {row[0]} with {row[1]}% reduction")
        ok("the JWS signature is kept verbatim (owner proof discards its own)") \
            if row[2].count(".") == 2 and len(row[2]) > 100 \
            else die("signature not stored")
        # And it still verifies out of the database - it is auditable later.
        hdr = jwt.get_unverified_header(row[2])
        ven_cert = x509.load_der_x509_certificate(base64.b64decode(hdr["x5c"][0]))
        pub = ven_cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        payload = jwt.decode(row[2], pub, algorithms=["RS256"])
        ok(f"re-verifies from storage: activation {payload['activation_id']}, "
           f"{payload['date']} {payload['time']}") \
            if payload["activation_id"] == act_id else die("stored evidence mismatch")

        print("G3: the user sees the verified participation from the app")
        r = requests.get(f"{MTLS}/participation", cert=uclient, verify=CA_FILE)
        parts = r.json()["participations"]
        ok(f"{len(parts)} participation(s) reported to the owner") \
            if any(p["activation_id"] == act_id for p in parts) \
            else die(f"participation not visible: {parts}")

        print("G4: the same execution cannot be claimed twice")
        stored = sqlite3.connect(str(DB_FILE)).execute(
            "SELECT jws FROM evidence WHERE activation_id=?", (act_id,)).fetchone()[0]
        r = requests.post(f"{MTLS}/evidence", json={"evidence": stored},
                          cert=VEN_CLIENT, verify=CA_FILE)
        ok(f"replayed evidence refused (409): {r.json()['error']}") \
            if r.status_code == 409 else die(f"expected 409, got {r.status_code}")

        print("G5: evidence must match the activation it claims")
        # Same activation, but the nonce is not the one the VPP issued.
        sys.path.insert(0, str(ROOT / "appliance"))
        import hsm
        hsm.initialize()
        bad_nonce = hsm.sign_jws({
            "activation_id": act_id, "ven": hsm.subject(),
            "date": "2026-08-10", "time": "15:00",
            "executed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reduction_pct": 50, "nonce": secrets.token_hex(16)},
            typ="application/dr-evidence+json")
        r = requests.post(f"{MTLS}/evidence", json={"evidence": bad_nonce},
                          cert=VEN_CLIENT, verify=CA_FILE)
        ok(f"wrong nonce refused: {r.json()['error']}") if r.status_code == 400 \
            else die(f"expected 400, got {r.status_code} {r.text}")

        unknown = hsm.sign_jws({
            "activation_id": "act-does-not-exist", "ven": hsm.subject(),
            "date": "2026-08-10", "time": "15:00",
            "executed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reduction_pct": 50, "nonce": secrets.token_hex(16)},
            typ="application/dr-evidence+json")
        r = requests.post(f"{MTLS}/evidence", json={"evidence": unknown},
                          cert=VEN_CLIENT, verify=CA_FILE)
        ok("evidence for an unknown activation refused") if r.status_code == 400 \
            else die(f"expected 400, got {r.status_code}")

        print("G6: only the certified appliance key can produce valid evidence")
        rogue_key, rogue_cert, _ = ra_identity(f"rogue-{secrets.token_hex(3)}")
        forged = sign_as(rogue_key, rogue_cert, {
            "activation_id": act_id, "ven": ven,
            "date": "2026-08-10", "time": "15:00",
            "executed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "reduction_pct": 100, "nonce": secrets.token_hex(16)},
            "application/dr-evidence+json")
        r = requests.post(f"{MTLS}/evidence", json={"evidence": forged},
                          cert=VEN_CLIENT, verify=CA_FILE)
        ok(f"evidence signed by another key refused: {r.json()['error'][:60]}...") \
            if r.status_code == 400 else die(f"expected 400, got {r.status_code}")

        print(f"\nEVIDENCE (OPERATIONAL 4) COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
