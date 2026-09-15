import base64
import datetime
import json
import math
import re
import sqlite3
import statistics
import subprocess
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
PY = sys.executable

sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability as av  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="eval_"))
summary = {
    "method": {
        "transport": "loopback (127.0.0.1), so these exclude network latency "
                     "and are a lower bound for any real deployment",
        "clock": "time.perf_counter around the client call, so they include "
                 "TLS, server work and client parsing",
        "warmup_discarded": None,   # filled once WARMUP is known
    },
    "timings_ms": {},
}


def run_cli(*args):
    r = subprocess.run([PY, *args], cwd=str(ROOT), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{args} failed:\n{r.stdout}\n{r.stderr}")
    return r.stdout


SAMPLES = 15   # repetitions of every operation that can be repeated
WARMUP = 2     # discarded: the first TLS handshake is not representative
summary["method"]["warmup_discarded"] = WARMUP
summary["method"]["samples_per_repeatable_op"] = SAMPLES


def timed(fn):
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1000.0


def _pct(values, q):
    """Nearest-rank percentile, well defined for any sample count."""
    ordered = sorted(values)
    return ordered[max(1, math.ceil(q * len(ordered))) - 1]


def record(label, values):
    """Distribution of a repeated operation. n is reported so the percentiles
    can be read for what they are worth."""
    summary["timings_ms"][label] = {
        "p50": round(statistics.median(values), 1),
        "p95": round(_pct(values, 0.95), 1),
        "min": round(min(values), 1),
        "max": round(max(values), 1),
        "n": len(values)}


def sample(label, fn, n=SAMPLES, warmup=WARMUP):
    for _ in range(warmup):
        fn()
    record(label, [timed(fn)[1] for _ in range(n)])


def once(label, ms, why):
    """A step that cannot be repeated without changing what it measures.
    Recorded as the single sample it is rather than dressed up as a median."""
    summary["timings_ms"][label] = {
        "ms": round(ms, 1), "n": 1, "single_sample": why}


def reset_operational_state():
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute("DELETE FROM evidence")
        c.execute("DELETE FROM activations")
        c.execute("DELETE FROM availability WHERE ven_subject LIKE 'CN=syn-%'")
        c.execute("DELETE FROM appliances WHERE ven_subject LIKE 'CN=syn-%'")
        c.execute("DELETE FROM users WHERE subject LIKE 'CN=syn-user-%'")


def ra_identity(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .sign(key, hashes.SHA256()))
    r = requests.post(
        f"{MAN}/ra/issue",
        json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
        verify=CA_FILE)
    r.raise_for_status()
    cert_pem = r.json()["certificate"]
    r2 = requests.post(f"{VPP}/enroll", json={"certificate": cert_pem},
                       verify=CA_FILE)
    r2.raise_for_status()
    cf, kf = tmp / f"{name}.crt", tmp / f"{name}.key"
    cf.write_text(cert_pem)
    kf.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key, cert_pem, (str(cf), str(kf))


def sign_as(key, cert_pem, payload, typ):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256",
                      headers={"x5c": [x5c], "typ": typ})


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def now_slot():
    n = now_utc()
    return n.hour * 2 + n.minute // 30


def slot_hhmm(s):
    return f"{s // 2:02d}:{(s % 2) * 30:02d}"


def main():
    print("== phase 0: reset + identities ==")
    reset_operational_state()
    key, cert_pem, client = ra_identity("eval-user-01")

    print(f"== phase 0b: issuance and enrolment, {SAMPLES} samples ==")
    issue_ms, enroll_ms = [], []
    for i in range(WARMUP + SAMPLES):
        throwaway = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(
                   NameOID.COMMON_NAME, f"eval-perf-{i:02d}")]))
               .sign(throwaway, hashes.SHA256()))
        (r, ms) = timed(lambda: requests.post(
            f"{MAN}/ra/issue",
            json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
            verify=CA_FILE))
        r.raise_for_status()
        pem = r.json()["certificate"]
        (r2, ms2) = timed(lambda: requests.post(
            f"{VPP}/enroll", json={"certificate": pem}, verify=CA_FILE))
        r2.raise_for_status()
        if i >= WARMUP:
            issue_ms.append(ms)
            enroll_ms.append(ms2)
    record("ra_issue", issue_ms)
    record("enroll", enroll_ms)

    bundle = sign_as(key, cert_pem, {
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text()}, "application/pairing+json")

    print(f"== phase 1: onboarding, {SAMPLES} samples ==")
    pair_ms, proof_ms = [], []
    ven = proof = None
    for i in range(WARMUP + SAMPLES):
        requests.post(f"{APP}/factory-reset")
        (r, ms) = timed(lambda: requests.post(f"{APP}/pair", json={"jws": bundle}))
        r.raise_for_status()
        proof = r.json()["owner_proof"]
        (r2, ms2) = timed(lambda: requests.post(
            f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
            cert=client, verify=CA_FILE))
        r2.raise_for_status()
        ven = r2.json()["ven"]
        if i >= WARMUP:
            pair_ms.append(ms)
            proof_ms.append(ms2)
    record("pair", pair_ms)
    record("owner_proof", proof_ms)
    summary["ven"] = ven

    calendar = {d: "1" * av.SLOTS_PER_DAY for d in av.DAYS}

    def declare():
        r = requests.post(
            f"{MTLS}/availability",
            json={"ven": ven, "jws": sign_as(
                key, cert_pem,
                {"slots": calendar, "version": int(time.time() * 1000)},
                "application/availability+json")},
            cert=client, verify=CA_FILE)
        r.raise_for_status()
        return r

    sample("availability_declare", declare)

    # warm-up poll: VEN self-registration + calendar adoption (not timed as RTT)
    (r, ms) = timed(lambda: requests.post(f"{APP}/poll"))
    r.raise_for_status()
    once("first_poll_register_adopt", ms,
         "the first poll after pairing, it registers the VEN and adopts the "
         "calendar, so a second call measures something else")
    summary["first_poll"] = r.json()

    print("== phase 2: end-to-end DR event on the real appliance ==")
    run_cli("backoffice/dr_operator.py", "init", "--force")
    day = av.DAYS[now_utc().weekday()]
    start = min(now_slot(), av.SLOTS_PER_DAY - 2)
    end = start + 2
    out = run_cli("backoffice/dr_operator.py", "activate", "--power", "1000",
                  "--day", day, "--from", slot_hhmm(start), "--to", slot_hhmm(end))
    summary["e2e_activate_output"] = out.strip()
    (r, ms) = timed(lambda: requests.post(f"{APP}/poll"))
    r.raise_for_status()
    once("delivering_poll", ms,
         "an activation is delivered once, and recovery blocks a prompt repeat")
    summary["e2e_poll"] = r.json()
    (r, ms) = timed(lambda: requests.post(f"{APP}/evidence"))
    r.raise_for_status()
    once("evidence_submit_verify", ms,
         "replaying the same evidence is refused with 409 by design")
    summary["e2e_evidence"] = r.json()
    def read_participation():
        r = requests.get(f"{MTLS}/participation", cert=client, verify=CA_FILE)
        r.raise_for_status()
        return r

    sample("participation_read", read_participation)
    summary["participation"] = read_participation().json()

    print("== phase 3: synthetic population ==")
    gen = run_cli("backoffice/population.py", "generate", "--users", "20", "--seed", "42")
    summary["population_generate_output"] = gen.strip()
    agg = run_cli("backoffice/population.py", "aggregate", "--day", day)
    summary["aggregate_view_day"] = day
    summary["aggregate_view_output"] = agg

    with sqlite3.connect(str(DB_FILE)) as c:
        rows = c.execute(
            """SELECT a.ven_subject, a.nominal_power, a.max_curtail, a.recovery,
                      v.slots
               FROM appliances a LEFT JOIN availability v
               ON v.ven_subject = a.ven_subject
               WHERE a.ven_subject LIKE 'CN=syn-%'""").fetchall()
    types = {}
    powers = []
    slot_power = [0] * av.SLOTS_PER_DAY
    for subject, p, mx, rec, slots_json in rows:
        m = re.search(r"CN=syn-([a-z]+)", subject)
        t = m.group(1) if m else "?"
        types[t] = types.get(t, 0) + 1
        powers.append(p)
        if slots_json:
            bitmap = json.loads(slots_json)[day]
            for i, b in enumerate(bitmap):
                if b == "1":
                    slot_power[i] += p
    peak_w = max(slot_power)
    peak_slot = slot_power.index(peak_w)
    summary["fleet"] = {
        "appliances": len(rows), "types": types,
        "power_min_w": min(powers), "power_max_w": max(powers),
        "total_power_w": sum(powers)}
    summary["availability_today"] = {
        "peak_w": peak_w, "peak_slot": peak_slot,
        "peak_slot_label": slot_hhmm(peak_slot),
        "at_event_slot_w": slot_power[start],
        "event_slot": start, "event_slot_label": slot_hhmm(start)}

    print("== phase 4: multi-household aggregation event (6 kW) ==")
    # (a) infeasible attempt in the population's dead zone (current slot, if empty)
    inf = run_cli("backoffice/dr_operator.py", "select", "--power", "6000",
                  "--day", day, "--from", slot_hhmm(start), "--to", slot_hhmm(end))
    summary["aggregation_infeasible_output"] = inf.strip()
    # (b) the real event at the population's peak for today
    pk_start = min(peak_slot, av.SLOTS_PER_DAY - 2)
    pk_end = pk_start + 2
    summary["aggregation_event_interval"] = f"{slot_hhmm(pk_start)}-{slot_hhmm(pk_end)}"
    sel = run_cli("backoffice/dr_operator.py", "select", "--power", "6000",
                  "--day", day, "--from", slot_hhmm(pk_start), "--to", slot_hhmm(pk_end))
    summary["aggregation_select_output"] = sel.strip()
    act = run_cli("backoffice/dr_operator.py", "activate", "--power", "6000",
                  "--day", day, "--from", slot_hhmm(pk_start), "--to", slot_hhmm(pk_end))
    summary["aggregation_activate_output"] = act.strip()

    print(f"== phase 5: empty polls, {SAMPLES} samples ==")

    def empty_poll():
        r = requests.post(f"{APP}/poll")
        r.raise_for_status()
        return r

    sample("empty_poll", empty_poll)

    print("== phase 6: cleanup ==")
    run_cli("backoffice/population.py", "clear")
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute("DELETE FROM evidence")
        c.execute("DELETE FROM activations")
        # the throwaway identities phase 0b enrolled to sample issuance
        c.execute("DELETE FROM users WHERE subject LIKE 'CN=eval-perf-%'")

    print("===SUMMARY===")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    finally:
        try:
            run_cli("backoffice/population.py", "clear")
        except Exception as e:
            print(f"cleanup warning: {e}")
