import base64
import datetime
import os
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

# Both addresses are site-specific, so they are taken from the command line or
# the environment rather than baked in:
#
#   python tests/verify_pi.py http://<pi-address>:8082 <this-pc-lan-address>
#   TFG_PI_URL=http://raspberrypi.local:8082 TFG_LAN_HOST=192.168.1.50 python tests/verify_pi.py
#
# <this-pc-lan-address> must be in the VPP certificate SAN; see EXTRA_SAN_IPS
# in certs/make_certs.sh.
PI = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TFG_PI_URL", "http://raspberrypi.local:8082")
LAN = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("TFG_LAN_HOST", "")

if not LAN:
    sys.exit(
        "This PC's LAN address is required so the Pi can reach the VPP."
        + '\n'
        + "  python tests/verify_pi.py <pi-url> <lan-address>"
        + '\n'
        + "  or set TFG_LAN_HOST=<lan-address>"
    )

VPP, MTLS = "https://127.0.0.1:8080", "https://127.0.0.1:8443"  # from this PC
VPP_FOR_PI = f"https://{LAN}:8080"                              # from the Pi
MTLS_FOR_PI = f"https://{LAN}:8443"

sys.path.insert(0, str(ROOT / "backoffice"))
sys.path.insert(0, str(ROOT / "vpp-server"))
import dr_operator  # noqa: E402
from app import availability as av  # noqa: E402

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="pi_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def ra_identity(name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .sign(key, hashes.SHA256()))
    r = requests.post("https://127.0.0.1:8081/ra/issue",
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


def user_jws(key, cert_pem: str, payload: dict) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256", headers={"x5c": [x5c]})


def reset_operational_state():
    with sqlite3.connect(str(ROOT / "vpp-server" / "vpp.db")) as c:
        c.execute("DELETE FROM evidence")
        c.execute("DELETE FROM activations")
        c.execute("DELETE FROM availability WHERE ven_subject LIKE 'CN=syn-%'")
        c.execute("DELETE FROM appliances WHERE ven_subject LIKE 'CN=syn-%'")
        c.execute("DELETE FROM users WHERE subject LIKE 'CN=syn-user-%'")


def current_window(slots: int = 4) -> dict:
    """A window covering *now* in UTC, started one slot early where possible
    so that a small clock skew between this PC and the Pi cannot leave the
    Pi's own wall clock outside the window."""
    now = datetime.datetime.now(datetime.timezone.utc)
    now_slot = now.hour * 2 + now.minute // 30
    start = max(0, min(now_slot, av.SLOTS_PER_DAY - slots) - 1)
    return {"day": av.DAYS[now.weekday()], "slot_start": start,
            "slot_end": start + slots}


def wait_until(probe, timeout_s: int = 90, step_s: int = 3):
    """Poll `probe` until it returns a truthy value or the timeout expires.

    The Pi polls the VTN on its own periodic loop, so the gate asserts on
    OUTCOMES (status, participation) rather than on which poll consumed the
    activation - the manual /poll just accelerates the happy path."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(step_s)
    return None


def main():
    print(f"Pi appliance: {PI}   VPP as seen from the Pi: {LAN}")

    print("G1: the physical appliance is reachable and factory-fresh")
    try:
        r = requests.get(f"{PI}/ping", timeout=5).json()
    except Exception as e:
        die(f"cannot reach the Pi at {PI}: {e}")
    requests.post(f"{PI}/factory-reset", timeout=5)
    state = requests.get(f"{PI}/ping", timeout=5).json()["state"]
    ok(f"appliance on the Pi answers (service {r['service']}), state={state}") \
        if state == 0 else die(f"expected state 0 after reset, got {state}")

    print("G2: user registration (RA + enroll) and pairing WITH THE PI")
    reset_operational_state()
    ukey, ucert, uclient = ra_identity(f"pi-user-{secrets.token_hex(3)}")
    bundle = user_jws(ukey, ucert, {
        "vpp_url": VPP_FOR_PI, "vpp_mtls_url": MTLS_FOR_PI,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text(),
    })
    r = requests.post(f"{PI}/pair", json={"jws": bundle}, timeout=15)
    if not r.ok:
        die(f"/pair -> {r.status_code} {r.text}")
    paired = r.json()
    ok(f"paired: owner={paired['owner']}, P={paired['parameters']['P']} W "
       f"(certified), max={paired['parameters']['max']}, rec={paired['parameters']['rec']}") \
        if paired["status"] == "paired" and paired["parameters"]["P"] == 2000 \
        else die(f"unexpected pair response {paired}")

    print("G3: the owner proof signed on the Pi binds it at the VPP")
    r = requests.post(f"{MTLS}/appliances/owner-proof",
                      json={"owner_proof": paired["owner_proof"]},
                      cert=uclient, verify=CA_FILE)
    if not r.ok:
        die(f"owner-proof -> {r.status_code} {r.text}")
    bound = r.json()
    ven = bound["ven"]
    ok(f"bound: {ven} -> {bound['owner']}") if bound["status"] == "bound" \
        else die(f"unexpected {bound}")

    print("G4: the signed calendar is declared at the VPP and adopted by the Pi")
    week = {d: "1" * av.SLOTS_PER_DAY for d in av.DAYS}  # this gate tests the flow
    cal_version = int(time.time() * 1000)
    r = requests.post(f"{MTLS}/availability",
                      json={"ven": ven,
                            "jws": user_jws(ukey, ucert,
                                            {"slots": week, "version": cal_version})},
                      cert=uclient, verify=CA_FILE)
    ok(f"VPP: {r.json()['status']} ({r.json()['declared_slots']} slots, "
       f"version {r.json()['version']})") \
        if r.ok and r.json()["status"] == "declared" else die(f"{r.status_code} {r.text}")
    # The Pi retrieves the owner-signed calendar through its own outbound poll.
    requests.post(f"{PI}/poll", timeout=20)
    adopted = wait_until(lambda: (lambda s: s if s.get("availability_version") ==
                                  cal_version else None)(
        requests.get(f"{PI}/status", timeout=10).json()), timeout_s=30)
    ok(f"Pi adopted it through its outbound poll (version {cal_version})") \
        if adopted else die("the Pi never adopted the signed calendar")

    print("G5: the Pi registers itself with the VTN (no external trigger)")
    # A poll cycle registers first if needed; the Pi's own periodic loop may
    # already have done it. Either way, the registration must be its own doing.
    requests.post(f"{PI}/poll", timeout=20)
    reg = wait_until(lambda: requests.get(f"{PI}/status", timeout=10)
                     .json().get("registration"), timeout_s=30)
    ok(f"self-registered: venID={reg['ven_id']} ({reg['registration_id']}), "
       f"polls every {reg['poll_seconds']} s") \
        if reg and reg.get("registration_id") else die(f"no self-registration: {reg}")

    print("G6: the operator activates; the Pi pulls, executes and testifies")
    crt, key = dr_operator.init_credential()
    r = requests.post(f"{MTLS}/dr/activate",
                      json={"power_w": 1000, **current_window(),
                            "action": "reduce"},
                      cert=(crt, key), verify=CA_FILE)
    if r.status_code != 200:
        die(f"/dr/activate -> {r.status_code} {r.text}")
    ok(f"activated: {[a['activation_id'] for a in r.json()['activations']]}")

    # The Pi pulls OUTBOUND over mutual TLS - through its own periodic loop or
    # through this manual acceleration, whichever comes first - and executes.
    requests.post(f"{PI}/poll", timeout=20)
    st = wait_until(lambda: (lambda s: s if s.get("executed_count", 0) >= 1 else None)(
        requests.get(f"{PI}/status", timeout=10).json()))
    ok(f"the Pi retrieved and executed the activation "
       f"(reduction {st['last_activation']['reduction_pct']}%)") \
        if st else die("the Pi never executed the activation")

    r = requests.post(f"{PI}/poll", timeout=20).json()
    ok("a further poll returns nothing (delivered exactly once)") \
        if r["polled"] == 0 else die(f"second poll -> {r}")

    # Evidence is signed on the Pi (its HSM) and submitted outbound.
    requests.post(f"{PI}/evidence", timeout=20)
    part = wait_until(lambda: (lambda b: b if b.get("count", 0) >= 1 else None)(
        requests.get(f"{MTLS}/participation", cert=uclient, verify=CA_FILE).json()))
    ok("evidence signed on the Pi reached the VPP and was verified") \
        if part else die("evidence never verified at the VPP")

    print("G7: the participation and its reward reach the user")
    p = part["participations"][0]
    ok(f"{part['count']} participation: {p.get('energy_kwh')} kWh -> "
       f"{p.get('reward_eur')} EUR (total {part['total_reward_eur']} EUR)") \
        if part["count"] == 1 and p.get("energy_kwh") == 2.0 \
        and p.get("reward_eur") == 0.3 else die(f"participation -> {part}")

    print(f"\nPHYSICAL APPLIANCE (RASPBERRY PI) COMPLETE: {passed} checks passed.")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
