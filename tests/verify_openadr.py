import json
import sqlite3
import sys
from pathlib import Path

from cryptography import x509

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certs"
CA_FILE = str(CERTS / "CA.crt")
DB_FILE = ROOT / "vpp-server" / "vpp.db"
MTLS = "https://127.0.0.1:8443"

sys.path.insert(0, str(ROOT / "appliance"))
import vtn_client  # noqa: E402

passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    sys.exit(1)


def main():
    ven_cert, ven_key = str(CERTS / "VEN.crt"), str(CERTS / "VEN.key")
    ven_subject = x509.load_pem_x509_certificate(
        (CERTS / "VEN.crt").read_bytes()).subject.rfc4514_string()
    profile = {"P": 2000, "max": 120, "rec": 30}

    print("G1: VEN registers with the VTN (oadrCreatePartyRegistration)")
    resp = vtn_client.register(MTLS, CA_FILE, ven_cert, ven_key,
                               "ac-livingroom", profile)
    ok("VTN accepted (oadrCreatedPartyRegistration, responseCode 200)") \
        if resp.get("oadrResponse", {}).get("responseCode") == 200 \
        else die(f"unexpected response: {resp}")
    reg_id, ven_id = resp.get("registrationID"), resp.get("venID")
    ok(f"registrationID assigned: {reg_id}") \
        if reg_id and reg_id.startswith("reg-") else die("no registrationID")
    ok(f"venID from the VEN certificate identity: {ven_id}") \
        if ven_id == "ven-0001" else die(f"unexpected venID {ven_id}")

    print("G2: the VTN stored the registration and the appliance profile")
    row = sqlite3.connect(str(DB_FILE)).execute(
        "SELECT registration_id, profile FROM vens WHERE ven_subject=?",
        (ven_subject,)).fetchone()
    ok("registration persisted at the VTN") if row and row[0] == reg_id \
        else die("registration not persisted")
    ok(f"reported appliance profile stored: {row[1]}") \
        if json.loads(row[1]) == profile else die(f"profile mismatch: {row[1]}")

    print("G3: re-registration is idempotent")
    resp2 = vtn_client.register(MTLS, CA_FILE, ven_cert, ven_key,
                                "ac-livingroom", profile)
    ok("re-register returns the same registrationID") \
        if resp2.get("registrationID") == reg_id else die("registrationID changed")

    print(f"\nVEN REGISTRATION (OPENADR) COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
