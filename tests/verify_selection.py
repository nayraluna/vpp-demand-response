import base64
import datetime
import secrets
import shutil
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
VPP, MTLS = "https://127.0.0.1:8080", "https://127.0.0.1:8443"
MAN, APP = "https://127.0.0.1:8081", "http://127.0.0.1:8082"

sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability as av  # noqa: E402
from app import scheduling  # noqa: E402

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="selection_"))
NOW = datetime.datetime(2026, 8, 9, 12, 0, tzinfo=datetime.timezone.utc)


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def always_available() -> dict:
    return {d: "1" * av.SLOTS_PER_DAY for d in av.DAYS}


def appliance(name, power, max_curtail=240, recovery=30, slots=None, last_end=None):
    return {"ven_subject": name, "nominal_power": power,
            "max_curtail": max_curtail, "recovery": recovery,
            "availability": always_available() if slots is None else slots,
            "last_activation_end": last_end}


# ----------------------------------------------------------------- Part A ---
def part_a():
    print("A1: the request is covered with the fewest appliances")
    fleet = [appliance("ac-1", 2000), appliance("fridge-1", 500),
             appliance("ac-2", 1500), appliance("heater-1", 3000)]
    r = scheduling.select(4000, "mon", av.slot_index(15), av.slot_index(17), fleet, NOW)
    if not r["feasible"]:
        die(f"expected feasible: {r}")
    ok(f"{r['appliance_count']} appliances give {r['aggregated_power']} W "
       f"for {r['requested_power']} W requested")
    ok("largest contributions chosen first (fewest households disturbed)") \
        if [s["ven"] for s in r["selected"]] == ["heater-1", "ac-1"] \
        else die(f"unexpected selection {r['selected']}")

    print("A2: appliances not available in the interval are excluded")
    week = av.empty_week()
    week["mon"] = "1" * av.slot_index(14) + "0" * (av.SLOTS_PER_DAY - av.slot_index(14))
    fleet = [appliance("ac-1", 2000, slots=week), appliance("ac-2", 2000)]
    r = scheduling.select(2000, "mon", av.slot_index(15), av.slot_index(17), fleet, NOW)
    ok("only the available appliance is selected") \
        if [s["ven"] for s in r["selected"]] == ["ac-2"] else die(str(r["selected"]))
    ok(f"the other is reported as rejected: {r['rejected'][0]['reason']}") \
        if r["rejected"] and "not available" in r["rejected"][0]["reason"] \
        else die(f"unexpected rejections {r['rejected']}")

    print("A3: the max curtailment time is respected")
    fleet = [appliance("ac-short", 5000, max_curtail=60)]
    r = scheduling.select(1000, "mon", av.slot_index(15), av.slot_index(18), fleet, NOW)
    ok(f"appliance excluded: {r['rejected'][0]['reason']}") \
        if not r["feasible"] and "exceeds its maximum" in r["rejected"][0]["reason"] \
        else die(f"unexpected {r}")

    print("A4: the recovery time is respected")
    recent = (NOW - datetime.timedelta(minutes=10)).isoformat()
    fleet = [appliance("ac-tired", 5000, recovery=60, last_end=recent)]
    r = scheduling.select(1000, "mon", av.slot_index(15), av.slot_index(16), fleet, NOW)
    ok(f"appliance excluded: {r['rejected'][0]['reason']}") \
        if not r["feasible"] and "still recovering" in r["rejected"][0]["reason"] \
        else die(f"unexpected {r}")

    long_ago = (NOW - datetime.timedelta(minutes=120)).isoformat()
    fleet = [appliance("ac-rested", 5000, recovery=60, last_end=long_ago)]
    r = scheduling.select(1000, "mon", av.slot_index(15), av.slot_index(16), fleet, NOW)
    ok("an appliance that has finished recovering is eligible again") \
        if r["feasible"] else die(f"expected feasible {r}")

    print("A5: infeasibility is reported explicitly, activating nobody")
    fleet = [appliance("ac-1", 1000), appliance("ac-2", 500)]
    r = scheduling.select(9000, "mon", av.slot_index(15), av.slot_index(16), fleet, NOW)
    if r["feasible"]:
        die("should not be feasible")
    ok(f"not possible: {r['available_power']} W available, "
       f"shortfall {r['shortfall']} W")
    ok("no appliance is activated when the request cannot be served") \
        if r["selected"] == [] else die("appliances selected despite infeasibility")


# ----------------------------------------------------------------- Part B ---
def reset_operational_state():
    """Test setup: drop activations/evidence left by an earlier run, so the
    appliance is not still inside a previous recovery window (which selection
    would correctly refuse) and the suite stays repeatable."""
    import sqlite3
    with sqlite3.connect(str(ROOT / "vpp-server" / "vpp.db")) as c:
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


def bind_and_declare(key, cert_pem, client, calendar) -> str:
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
    ven = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                        cert=client, verify=CA_FILE).json()["ven"]
    r = requests.post(
        f"{MTLS}/availability",
        json={"ven": ven,
              "jws": jwt.encode({"slots": calendar,
                                 "version": int(time.time() * 1000)},
                                key_pem, algorithm="RS256",
                                headers={"x5c": [x5c],
                                         "typ": "application/availability+json"})},
        cert=client, verify=CA_FILE)
    if not r.ok:
        die(f"VPP /availability -> {r.status_code} {r.text}")
    return ven


def part_b():
    print("B1: only the DR operator may request a reduction")
    reset_operational_state()
    ukey, ucert, uclient = ra_identity(f"user-{secrets.token_hex(3)}")
    week = av.empty_week()
    start, end = av.slot_index(15), av.slot_index(19)
    week["mon"] = "0" * start + "1" * (end - start) + "0" * (av.SLOTS_PER_DAY - end)
    ven = bind_and_declare(ukey, ucert, uclient, week)

    # Inside the declared window, and exactly the appliance's max curtailment
    # time (120 min) - the boundary case must still be eligible.
    request = {"power_w": 1000, "day": "mon",
               "slot_start": start, "slot_end": av.slot_index(17)}
    r = requests.post(f"{MTLS}/dr/select", json=request, cert=uclient, verify=CA_FILE)
    ok("an ordinary user is refused (403)") if r.status_code == 403 \
        else die(f"expected 403, got {r.status_code}")

    _ok, _oc, operator = ra_identity(f"dr-{secrets.token_hex(3)}", "role=operator")

    print("B2: the operator gets a selection inside the declared window")
    r = requests.post(f"{MTLS}/dr/select", json=request, cert=operator, verify=CA_FILE)
    if r.status_code != 200:
        die(f"expected 200, got {r.status_code} {r.text}")
    body = r.json()
    ok(f"feasible: {body['appliance_count']} appliance(s), "
       f"{body['aggregated_power']} W in {body['interval']} "
       f"({body['duration_minutes']} min = its exact max)") \
        if body["feasible"] and any(s["ven"] == ven for s in body["selected"]) \
        else die(f"expected our appliance selected: {body}")

    print("B3: an interval longer than the appliance's max is refused")
    too_long = {"power_w": 1000, "day": "mon", "slot_start": start, "slot_end": end}
    r = requests.post(f"{MTLS}/dr/select", json=too_long, cert=operator, verify=CA_FILE)
    body = r.json()
    ok(f"not possible: {body['rejected'][0]['reason']}") \
        if not body["feasible"] and "exceeds its maximum" in body["rejected"][0]["reason"] \
        else die(f"expected max violation: {body}")

    print("B4: outside the declared window the request cannot be served")
    night = {"power_w": 1000, "day": "mon",
             "slot_start": av.slot_index(3), "slot_end": av.slot_index(4)}
    r = requests.post(f"{MTLS}/dr/select", json=night, cert=operator, verify=CA_FILE)
    body = r.json()
    ok(f"not possible: {body['reason']}") if not body["feasible"] \
        else die("should not be feasible at night")

    print("B5: malformed requests are refused")
    r = requests.post(f"{MTLS}/dr/select",
                      json={"power_w": 100, "day": "funday",
                            "slot_start": 0, "slot_end": 1},
                      cert=operator, verify=CA_FILE)
    ok("unknown weekday refused (400)") if r.status_code == 400 \
        else die(f"expected 400, got {r.status_code}")
    r = requests.post(f"{MTLS}/dr/select",
                      json={"power_w": 100, "day": "mon",
                            "slot_start": 20, "slot_end": 5},
                      cert=operator, verify=CA_FILE)
    ok("inverted slot range refused (400)") if r.status_code == 400 \
        else die(f"expected 400, got {r.status_code}")


def main():
    try:
        part_a()
        part_b()
        print(f"\nSELECTION (OPERATIONAL 2) COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
