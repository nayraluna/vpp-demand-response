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

sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability  # noqa: E402

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="availability_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def enrolled_user(name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .sign(key, hashes.SHA256()))
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


def bind_appliance(key, cert_pem: str, client) -> str:
    """Pair the appliance as this user and register the ownership at the VPP."""
    requests.post(f"{APP}/factory-reset")
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    token = jwt.encode({"vpp_url": VPP, "vpp_mtls_url": MTLS,
                        "cert_vpp": (CERTS / "vpp.crt").read_text(),
                        "cert_ra": (CERTS / "CA.crt").read_text()},
                       key_pem, algorithm="RS256",
                       headers={"x5c": [x5c], "typ": "application/pairing+json"})
    proof = requests.post(f"{APP}/pair", json={"jws": token}).json()["owner_proof"]
    r = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                      cert=client, verify=CA_FILE)
    if r.status_code != 200:
        die(f"owner proof -> {r.status_code} {r.text}")
    return r.json()["ven"]


def weekday_calendar() -> dict:
    """Curtailable on weekday afternoons (15:00-19:00), never at night or weekends -
    the example from the Design chapter."""
    week = availability.empty_week()
    start, end = availability.slot_index(15), availability.slot_index(19)
    for day in ("mon", "tue", "wed", "thu", "fri"):
        bitmap = list(week[day])
        for i in range(start, end):
            bitmap[i] = "1"
        week[day] = "".join(bitmap)
    return week


def sign_calendar(key, cert_pem: str, slots: dict, version: int) -> str:
    """The owner-signed calendar JWS the mobile application produces."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode({"slots": slots, "version": version}, key_pem,
                      algorithm="RS256",
                      headers={"x5c": [x5c], "typ": "application/availability+json"})


def main():
    try:
        ukey, ucert, uclient = enrolled_user(f"user-{secrets.token_hex(3)}")
        ven = bind_appliance(ukey, ucert, uclient)
        calendar = weekday_calendar()
        version = int(time.time() * 1000)

        print("G1: the owner declares a signed weekly availability calendar")
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": ven,
                                "jws": sign_calendar(ukey, ucert, calendar, version)},
                          cert=uclient, verify=CA_FILE)
        if r.status_code != 200:
            die(f"expected 200, got {r.status_code} {r.text}")
        body = r.json()
        expected = 5 * (availability.slot_index(19) - availability.slot_index(15))
        ok(f"declared, {body['declared_slots']} slots of {body['slot_minutes']} min "
           f"(version {body['version']})") \
            if body["declared_slots"] == expected and body["version"] == version \
            else die(f"expected {expected} slots at version {version}, got {body}")

        # The appliance retrieves the signed calendar through its own poll.
        r = requests.post(f"{APP}/poll")
        if not r.ok:
            die(f"appliance poll -> {r.status_code} {r.text}")
        st = requests.get(f"{APP}/status").json()
        ok(f"appliance adopted it via outbound poll (version {st['availability_version']})") \
            if st["availability_declared"] and st["availability_version"] == version \
            else die(f"appliance did not adopt the calendar: {st}")

        print("G2: reading it back returns the calendar and the appliance parameters")
        r = requests.get(f"{MTLS}/availability", cert=uclient, verify=CA_FILE)
        appliances = r.json()["appliances"]
        mine = [a for a in appliances if a["ven_subject"] == ven]
        if not mine:
            die("appliance not listed for its owner")
        got = mine[0]
        ok(f"calendar persisted for {got['ven_subject']}") \
            if got["availability"] == calendar else die("calendar does not match")
        ok(f"parameters alongside: P={got['nominal_power']} "
           f"max={got['max_curtail']} rec={got['recovery']}") \
            if got["nominal_power"] == 2000 else die("parameters missing")

        print("G3: only the owner may declare availability")
        okey, ocert, other = enrolled_user(f"user-{secrets.token_hex(3)}")
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": ven,
                                "jws": sign_calendar(okey, ocert, calendar,
                                                     version + 1)},
                          cert=other, verify=CA_FILE)
        ok("a non-owner is refused (403)") if r.status_code == 403 \
            else die(f"expected 403, got {r.status_code}")
        r = requests.get(f"{MTLS}/availability", cert=other, verify=CA_FILE)
        ok("a non-owner sees no appliances of its own") \
            if r.json()["appliances"] == [] else die("leaked another user's appliances")

        print("G4: malformed calendars are refused")
        short = dict(calendar); short["mon"] = "101"
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": ven,
                                "jws": sign_calendar(ukey, ucert, short, version + 1)},
                          cert=uclient, verify=CA_FILE)
        ok("wrong number of slots refused (400)") if r.status_code == 400 \
            else die(f"expected 400, got {r.status_code}")

        bad = dict(calendar); bad["tue"] = "x" * availability.SLOTS_PER_DAY
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": ven,
                                "jws": sign_calendar(ukey, ucert, bad, version + 1)},
                          cert=uclient, verify=CA_FILE)
        ok("non-binary bitmap refused (400)") if r.status_code == 400 \
            else die(f"expected 400, got {r.status_code}")

        incomplete = {d: v for d, v in calendar.items() if d != "sun"}
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": ven,
                                "jws": sign_calendar(ukey, ucert, incomplete,
                                                     version + 1)},
                          cert=uclient, verify=CA_FILE)
        ok("missing weekday refused (400)") if r.status_code == 400 \
            else die(f"expected 400, got {r.status_code}")

        print("G5: unknown appliance")
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": "CN=nobody",
                                "jws": sign_calendar(ukey, ucert, calendar,
                                                     version + 1)},
                          cert=uclient, verify=CA_FILE)
        ok("unknown appliance refused (404)") if r.status_code == 404 \
            else die(f"expected 404, got {r.status_code}")

        print("G6: a validly signed but OLD calendar version is refused")
        r = requests.post(f"{MTLS}/availability",
                          json={"ven": ven,
                                "jws": sign_calendar(ukey, ucert, calendar, 1)},
                          cert=uclient, verify=CA_FILE)
        ok(f"stale version refused (400): {r.json()['error']}") \
            if r.status_code == 400 and "stale" in r.json()["error"] \
            else die(f"expected 400 stale, got {r.status_code} {r.text}")

        print("G7: a rolled-back calendar is refused by the appliance itself")
        # Simulate a misbehaving VPP: plant an old, fully permissive calendar
        # (validly signed by the owner, version 1) in the row the poll relays.
        permissive = {d: "1" * availability.SLOTS_PER_DAY for d in availability.DAYS}
        rollback = sign_calendar(ukey, ucert, permissive, 1)
        with sqlite3.connect(str(DB_FILE)) as c:
            c.execute("UPDATE availability SET jws=?, version=1 WHERE ven_subject=?",
                      (rollback, ven))
        body = requests.post(f"{APP}/poll").json()
        outcome = body.get("calendar") or {}
        ok(f"appliance refused the rollback: {outcome.get('reason')}") \
            if outcome.get("status") == "refused" \
            and "stale" in outcome.get("reason", "") \
            else die(f"rollback not refused: {body}")
        st = requests.get(f"{APP}/status").json()
        ok(f"appliance keeps its newer calendar (version {st['availability_version']})") \
            if st["availability_version"] == version \
            else die(f"appliance lost its newer calendar: {st}")

        print("G8: a forged owner certificate outside the CA chain is refused")
        # The strongest misbehaving-VPP move: it cannot steal the owner's key,
        # so it mints a SELF-SIGNED certificate bearing the owner's exact
        # subject and signs a permissive calendar with a NEWER version. The
        # signature verifies against the forged certificate and the subject
        # matches the recorded owner; only the chain check (signer certified
        # by the CA delivered at pairing) stands between this and adoption.
        owner_subject = x509.load_pem_x509_certificate(ucert.encode()).subject
        fkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        forged_cert = (x509.CertificateBuilder()
                       .subject_name(owner_subject)
                       .issuer_name(owner_subject)
                       .public_key(fkey.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(now)
                       .not_valid_after(now + datetime.timedelta(days=1))
                       .sign(fkey, hashes.SHA256()))
        forged_pem = forged_cert.public_bytes(serialization.Encoding.PEM).decode()
        forged = sign_calendar(fkey, forged_pem, permissive, version + 10)
        with sqlite3.connect(str(DB_FILE)) as c:
            c.execute("UPDATE availability SET jws=?, version=? WHERE ven_subject=?",
                      (forged, version + 10, ven))
        body = requests.post(f"{APP}/poll").json()
        outcome = body.get("calendar") or {}
        ok(f"appliance refused the forged signer: {outcome.get('reason')}") \
            if outcome.get("status") == "refused" \
            and "not certified" in outcome.get("reason", "") \
            else die(f"forged-signer calendar not refused: {body}")
        st = requests.get(f"{APP}/status").json()
        ok(f"appliance keeps the owner's calendar (version {st['availability_version']})") \
            if st["availability_version"] == version \
            else die(f"appliance adopted a forged calendar: {st}")

        print(f"\nAVAILABILITY (OPERATIONAL 1) COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
