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
from app import remuneration  # noqa: E402

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="remuneration_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def reset_operational_state():
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


def full_calendar() -> dict:
    """Full availability: this gate is about remuneration, not the calendar."""
    return {day: "1" * av.SLOTS_PER_DAY for day in av.DAYS}


def current_window(slots: int = 4) -> dict:
    """A window covering *now* (UTC): the appliance only executes inside it."""
    now = datetime.datetime.now(datetime.timezone.utc)
    start = min(now.hour * 2 + now.minute // 30, av.SLOTS_PER_DAY - slots)
    return {"day": av.DAYS[now.weekday()], "slot_start": start,
            "slot_end": start + slots}


def onboard(key, cert_pem, client, calendar) -> str:
    requests.post(f"{APP}/factory-reset")
    bundle = sign_as(key, cert_pem, {
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text()}, "application/pairing+json")
    proof = requests.post(f"{APP}/pair", json={"jws": bundle}).json()["owner_proof"]
    ven = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                        cert=client, verify=CA_FILE).json()["ven"]
    # No VEN registration and no calendar delivery here: the appliance obtains
    # both autonomously through its first outbound poll.
    requests.post(
        f"{MTLS}/availability",
        json={"ven": ven,
              "jws": sign_as(key, cert_pem,
                             {"slots": calendar, "version": int(time.time() * 1000)},
                             "application/availability+json")},
        cert=client, verify=CA_FILE)
    return ven


def main():
    try:
        print("G1: the arithmetic, checked independently of the server")
        # 2000 W shed by 50% for 2 h -> 1000 W x 2 h = 2 kWh
        kwh = remuneration.energy_not_consumed_kwh(
            2000, 50, av.slot_index(15), av.slot_index(17))
        ok(f"2000 W at 50% for 2 h -> {kwh} kWh") if kwh == 2.0 \
            else die(f"expected 2.0 kWh, got {kwh}")
        eur = remuneration.reward_eur(kwh, 0.15)
        ok(f"at 0.15 EUR/kWh -> {eur} EUR") if eur == 0.3 \
            else die(f"expected 0.3 EUR, got {eur}")
        # A full shutdown sheds the whole nominal power.
        kwh_off = remuneration.energy_not_consumed_kwh(
            2000, 100, av.slot_index(15), av.slot_index(16))
        ok(f"a shutdown for 1 h sheds the full 2000 W -> {kwh_off} kWh") \
            if kwh_off == 2.0 else die(f"expected 2.0, got {kwh_off}")

        reset_operational_state()
        calendar = full_calendar()
        ukey, ucert, uclient = ra_identity(f"user-{secrets.token_hex(3)}")
        ven = onboard(ukey, ucert, uclient, calendar)
        _k, _c, operator = ra_identity(f"dr-{secrets.token_hex(3)}", "role=operator")

        print("G2: a user with no participation earns nothing")
        r = requests.get(f"{MTLS}/participation", cert=uclient, verify=CA_FILE)
        body = r.json()
        ok(f"no participation -> {body['total_reward_eur']} EUR") \
            if body["count"] == 0 and body["total_reward_eur"] == 0 \
            else die(f"expected zero, got {body}")

        print("G3: after a verified curtailment the owner sees what they earned")
        # The window covers *now* and lasts 2 h -> the 2.0 kWh checked below.
        requests.post(f"{MTLS}/dr/activate",
                      json={"power_w": 1000, **current_window(),
                            "action": "reduce"},
                      cert=operator, verify=CA_FILE)
        requests.post(f"{APP}/poll")
        requests.post(f"{APP}/evidence")

        r = requests.get(f"{MTLS}/participation", cert=uclient, verify=CA_FILE)
        body = r.json()
        if body["count"] != 1:
            die(f"expected one participation, got {body}")
        part = body["participations"][0]
        ok(f"{part['interval']} at {part['reduction_pct']}% of "
           f"{part['nominal_power']} W -> {part['energy_kwh']} kWh") \
            if part["energy_kwh"] == 2.0 else die(f"unexpected energy: {part}")
        ok(f"reward reported to the user: {part['reward_eur']} EUR "
           f"at {part['price_eur_per_kwh']} EUR/kWh") \
            if part["reward_eur"] == 0.3 else die(f"unexpected reward: {part}")
        ok(f"totals add up: {body['total_energy_kwh']} kWh, "
           f"{body['total_reward_eur']} EUR") \
            if body["total_energy_kwh"] == 2.0 and body["total_reward_eur"] == 0.3 \
            else die(f"totals wrong: {body}")

        print("G4: an activation without verified evidence earns nothing")
        # Issue an activation directly, and never submit evidence for it.
        with sqlite3.connect(str(DB_FILE)) as c:
            c.execute(
                """INSERT INTO activations(activation_id, ven_subject, day,
                       slot_start, slot_end, action, nonce, issued_at, ends_at,
                       delivered_at)
                   VALUES('act-unproven',?,'tue',?,?,'reduce',?,
                          '2026-01-01T00:00:00+00:00',NULL,NULL)""",
                (ven, av.slot_index(15), av.slot_index(17), secrets.token_hex(16)))
        r = requests.get(f"{MTLS}/participation", cert=uclient, verify=CA_FILE)
        after = r.json()
        ok("an unproven activation adds no reward "
           f"({after['count']} participation, {after['total_reward_eur']} EUR)") \
            if after["count"] == 1 and after["total_reward_eur"] == 0.3 \
            else die(f"unproven activation was paid: {after}")

        print("G5: another user does not see this participation")
        _uk, _uc, other = ra_identity(f"user-{secrets.token_hex(3)}")
        r = requests.get(f"{MTLS}/participation", cert=other, verify=CA_FILE)
        ok("a different user sees no participations and no reward") \
            if r.json()["count"] == 0 and r.json()["total_reward_eur"] == 0 \
            else die(f"leaked another user's participation: {r.json()}")

        print(f"\nREMUNERATION (OPERATIONAL 5) COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
