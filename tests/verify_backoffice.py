import json
import sqlite3
import sys
from pathlib import Path

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backoffice"))
sys.path.insert(0, str(ROOT / "vpp-server"))
import dr_operator  # noqa: E402
import population  # noqa: E402
from app import db  # noqa: E402

CERTS = ROOT / "certs"
CA_FILE = str(CERTS / "CA.crt")
MTLS = "https://127.0.0.1:8443"

passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    population.clear()
    sys.exit(1)


def stable(doc: dict):
    """The population without timestamps, for equality comparisons."""
    return [(u["subject"],
             [(a["ven"], a["nominal_power"], a["max_curtail"], a["recovery"],
               a["availability"]) for a in u["appliances"]])
            for u in doc["users"]]


def syn_counts() -> tuple[int, int]:
    with sqlite3.connect(db.DB_FILE) as c:
        users = c.execute("SELECT COUNT(*) FROM users WHERE subject LIKE "
                          "'CN=syn-user-%'").fetchone()[0]
        apps = c.execute("SELECT COUNT(*) FROM appliances WHERE ven_subject LIKE "
                         "'CN=syn-%'").fetchone()[0]
    return users, apps


def main():
    db.initialize()
    try:
        print("G1: a deterministic population is generated")
        r = population.generate(users=20, seed=7)
        ok(f"20 users with {r['appliances']} appliances") \
            if r["users"] == 20 and 20 <= r["appliances"] <= 60 \
            else die(f"unexpected population {r}")
        doc1 = population.export_doc()
        population.generate(users=20, seed=7)
        doc2 = population.export_doc()
        ok("same seed -> identical population") \
            if stable(doc1) == stable(doc2) else die("seed 7 not deterministic")
        population.generate(users=20, seed=8)
        ok("different seed -> different population") \
            if stable(population.export_doc()) != stable(doc1) \
            else die("different seeds produced the same population")
        population.generate(users=20, seed=7)

        print("G2: view 1 lists every appliance's parameters")
        text = population.view_appliances()
        ok("synthetic appliances listed with P/max/rec") \
            if "CN=syn-" in text and "P (W)" in text else die("view 1 incomplete")

        print("G3: view 2 aggregates available power per slot")
        # Independent hand-check of one slot (mon 18:00 = slot 36) straight
        # from the DB, against what the view reports.
        with sqlite3.connect(db.DB_FILE) as c:
            rows = c.execute(
                """SELECT a.nominal_power, v.slots FROM appliances a
                   JOIN availability v ON v.ven_subject = a.ven_subject"""
            ).fetchall()
        expected = sum(p for p, slots in rows if json.loads(slots)["mon"][36] == "1")
        got = population.aggregate_data("mon")[36]
        ok(f"mon 18:00 -> {got['power_w']} W across {got['count']} appliances") \
            if got["power_w"] == expected and got["count"] > 0 \
            else die(f"aggregate says {got}, DB says {expected}")

        print("G4: export -> clear -> import round trip")
        doc = population.export_doc()
        with sqlite3.connect(db.DB_FILE) as c:
            real_before = c.execute("SELECT COUNT(*) FROM appliances WHERE "
                                    "ven_subject NOT LIKE 'CN=syn-%'").fetchone()[0]
        population.clear()
        users, apps = syn_counts()
        with sqlite3.connect(db.DB_FILE) as c:
            real_after = c.execute("SELECT COUNT(*) FROM appliances WHERE "
                                   "ven_subject NOT LIKE 'CN=syn-%'").fetchone()[0]
        ok("clear removes only synthetic rows") \
            if (users, apps) == (0, 0) and real_before == real_after \
            else die(f"after clear: syn={users}/{apps}, real {real_before}->{real_after}")
        population.import_doc(doc)
        ok("import restores the exported population") \
            if stable(population.export_doc()) == stable(doc) \
            else die("imported population differs from the exported one")

        print("G5: the RA issues the operator credential")
        crt, key = dr_operator.init_credential(force=True)
        cert = x509.load_pem_x509_certificate(Path(crt).read_bytes())
        ous = [a.value for a in cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME)]
        ok(f"subject {cert.subject.rfc4514_string()} carries role=operator") \
            if "role=operator" in ous else die(f"unexpected OUs {ous}")

        print("G6: a large reduction is served by many synthetic households")
        # mon 18:00-18:30: inside the worker and evening profiles, and short
        # enough (30 min) for every appliance type including the fridge.
        request = {"power_w": 6000, "day": "mon", "slot_start": 36, "slot_end": 37}
        r = requests.post(f"{MTLS}/dr/select", json=request,
                          cert=(crt, key), verify=CA_FILE)
        if r.status_code != 200:
            die(f"/dr/select -> {r.status_code} {r.text}")
        body = r.json()
        ok(f"feasible: {body['appliance_count']} appliances aggregate "
           f"{body['aggregated_power']} W for the requested 6000 W") \
            if body["feasible"] and body["appliance_count"] >= 3 \
            and body["aggregated_power"] >= 6000 \
            else die(f"expected an aggregated selection: {body}")
        ok("the aggregation spans several households") \
            if len({s["ven"].rsplit("-", 1)[0] for s in body["selected"]}) >= 2 \
            else die(f"single household served everything: {body['selected']}")

        print("G7: without role=operator the trigger is refused")
        r = requests.post(f"{MTLS}/dr/select", json=request,
                          cert=(str(CERTS / "VEN.crt"), str(CERTS / "VEN.key")),
                          verify=CA_FILE)
        ok("a non-operator certificate is refused (403)") \
            if r.status_code == 403 else die(f"expected 403, got {r.status_code}")

        print(f"\nBACKOFFICE COMPLETE: {passed} checks passed.")
    finally:
        population.clear()


if __name__ == "__main__":
    main()
