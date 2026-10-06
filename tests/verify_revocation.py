import base64
import datetime
import json
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
CONFIG = ROOT / "appliance" / "config.json"
VPP = "https://127.0.0.1:8080"
CA = "https://127.0.0.1:8081"
MTLS = "https://127.0.0.1:8443"
APP = "http://127.0.0.1:8082"
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="revocation_gate_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def write_pair(name: str, key, cert_pem: str):
    kf, cf = tmp / f"{name}.key", tmp / f"{name}.crt"
    kf.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    cf.write_text(cert_pem)
    return str(cf), str(kf)


def ra_identity(cn: str, role: str | None = None):
    """A CA-issued identity. With a role, the subject carries OU=role=<role>,
    which is how the operator is recognised today."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if role:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"role={role}"))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name(attrs)).sign(key, hashes.SHA256()))
    r = requests.post(f"{CA}/ra/issue",
                      json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
                      verify=CA_FILE)
    if not r.ok:
        die(f"/ra/issue -> {r.status_code} {r.text}")
    pem = r.json()["certificate"]
    cert = x509.load_pem_x509_certificate(pem.encode())
    return key, pem, cert, format(cert.serial_number, "x")


def self_signed(cn: str, role: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"role={role}")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def sign_as(key, cert_pem: str, payload: dict, typ: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256", headers={"x5c": [x5c], "typ": typ})


def revoke(key, cert_pem: str, serial: str, reason="keyCompromise"):
    token = sign_as(key, cert_pem, {"serial": serial, "reason": reason},
                    "application/revocation-request+json")
    return requests.post(f"{CA}/ra/revoke", json={"request": token}, verify=CA_FILE)


def anchor_pem() -> bytes:
    return x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def fetch_crl() -> tuple[str, dict]:
    r = requests.get(f"{CA}/ra/crl", verify=CA_FILE)
    r.raise_for_status()
    token = r.json()["crl"]
    return token, jwt.decode(token, anchor_pem(), algorithms=["RS256"])


def listed(payload: dict, serial: str) -> bool:
    return any(e["serial"] == serial for e in payload["revoked"])


def onboard(key, cert_pem: str, client) -> str:
    """Pair the appliance to this identity and declare a fully open calendar.
    Registration and calendar delivery happen on the appliance's own poll."""
    requests.post(f"{APP}/factory-reset")
    bundle = sign_as(key, cert_pem, {
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text()}, "application/pairing+json")
    proof = requests.post(f"{APP}/pair", json={"jws": bundle}).json()["owner_proof"]
    ven = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                        cert=client, verify=CA_FILE).json()["ven"]
    calendar = {d: "1" * 48 for d in DAYS}
    r = requests.post(f"{MTLS}/availability",
                      json={"ven": ven, "jws": sign_as(
                          key, cert_pem, {"slots": calendar, "version": int(time.time() * 1000)},
                          "application/availability+json")},
                      cert=client, verify=CA_FILE)
    if not r.ok:
        die(f"/availability -> {r.status_code} {r.text}")
    return ven


def plant_crl(token: str) -> None:
    """Simulate a misbehaving VPP: replace the relay copy the poll serves. The
    number column is set high so the VPP's own refresh does not overwrite the
    plant, which is what an attacker holding the database would do."""
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute("INSERT INTO crl(id, jws, crl_number, fetched_at) VALUES(1, ?, 999999, 'planted')"
                  " ON CONFLICT(id) DO UPDATE SET jws=excluded.jws,"
                  " crl_number=excluded.crl_number, fetched_at=excluded.fetched_at", (token,))


def clear_crl() -> None:
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute("DELETE FROM crl")


def inject_activation(ven: str, act_id: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    slot = now.hour * 2 + now.minute // 30
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute(
            """INSERT INTO activations(activation_id, ven_subject, day, slot_start, slot_end,
                   action, nonce, issued_at, ends_at, delivered_at)
               VALUES(?,?,?,?,?,'reduce',?,?,NULL,NULL)""",
            (act_id, ven, DAYS[now.weekday()], slot, min(slot + 1, 48),
             secrets.token_hex(16), now.isoformat()))


def forged_crl(number: int) -> str:
    """A list signed by a self-made root: valid signature, wrong key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {"issuer": "CN=Fake CA", "crl_number": number, "this_update": now.isoformat(),
               "next_update": (now + datetime.timedelta(days=1)).isoformat(), "revoked": []}
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256", headers={"typ": "application/crl+json"})


def main():
    try:
        print("G1: a fresh user authenticates, and the CRL verifies against the CA root")
        ukey, upem, ucert, userial = ra_identity(f"user-{secrets.token_hex(3)}")
        requests.post(f"{VPP}/enroll", json={"certificate": upem}, verify=CA_FILE)
        ucf, ukf = write_pair("user", ukey, upem)
        r = requests.get(f"{MTLS}/session", cert=(ucf, ukf), verify=CA_FILE)
        ok(f"user authenticated over mTLS ({r.json()['user']})") if r.status_code == 200 \
            else die(f"expected 200, got {r.status_code} {r.text}")
        stale_token, crl = fetch_crl()
        n0 = crl["crl_number"]
        ok(f"CRL #{n0} signed by the CA, issuer {crl['issuer']}")
        ok("the new certificate is not listed") if not listed(crl, userial) \
            else die("fresh certificate already in the CRL")

        print("G2: only an operator may revoke")
        pkey, ppem, _, _ = ra_identity(f"plain-{secrets.token_hex(3)}")
        r = revoke(pkey, ppem, userial)
        ok(f"a CA-issued identity without the operator role is refused ({r.status_code})") \
            if r.status_code == 403 else die(f"expected 403, got {r.status_code} {r.text}")
        skey, spem = self_signed("fake-operator", "operator")
        r = revoke(skey, spem, userial)
        ok(f"an operator role on a certificate outside the CA is refused ({r.status_code})") \
            if r.status_code == 400 else die(f"expected 400, got {r.status_code} {r.text}")
        r = requests.get(f"{MTLS}/session", cert=(ucf, ukf), verify=CA_FILE)
        ok("the user is still authenticated after the refused attempts") \
            if r.status_code == 200 else die(f"user lost access: {r.status_code}")

        print("G3: the operator revokes, and the list moves forward")
        okey, opem, _, _ = ra_identity(f"op-{secrets.token_hex(3)}", role="operator")
        r = revoke(okey, opem, userial, "keyCompromise")
        body = r.json()
        ok(f"revoked {body['revoked']} by {body['requested_by']}") if r.status_code == 200 \
            else die(f"expected 200, got {r.status_code} {r.text}")
        _, crl = fetch_crl()
        ok(f"CRL number went from {n0} to {crl['crl_number']}") \
            if crl["crl_number"] == n0 + 1 else die(f"CRL number {crl['crl_number']}, expected {n0 + 1}")
        ok("the revoked serial is listed with its reason") \
            if listed(crl, userial) and any(e["reason"] == "keyCompromise" for e in crl["revoked"]) \
            else die("revoked serial missing from the CRL")

        print("G4: the VPP refuses the revoked certificate everywhere it enters")
        r = requests.get(f"{MTLS}/session", cert=(ucf, ukf), verify=CA_FILE)
        ok(f"mutual TLS request refused after revocation ({r.status_code}: {r.json()['error']})") \
            if r.status_code == 403 else die(f"expected 403, got {r.status_code} {r.text}")
        r = requests.post(f"{VPP}/enroll", json={"certificate": upem}, verify=CA_FILE)
        ok(f"re-enrolment with the revoked certificate refused ({r.status_code})") \
            if r.status_code == 403 else die(f"expected 403, got {r.status_code} {r.text}")

        print("G5: revocation is idempotent and only for certificates the CA issued")
        r = revoke(okey, opem, userial)
        ok(f"revoking twice is refused ({r.status_code})") if r.status_code == 409 \
            else die(f"expected 409, got {r.status_code} {r.text}")
        r = revoke(okey, opem, "deadbeef")
        ok(f"a serial this CA never issued is refused ({r.status_code})") if r.status_code == 404 \
            else die(f"expected 404, got {r.status_code} {r.text}")

        print("G6: a revoked operator cannot revoke anyone else")
        o2key, o2pem, _, o2serial = ra_identity(f"op-{secrets.token_hex(3)}", role="operator")
        _, _, _, vserial = ra_identity(f"victim-{secrets.token_hex(3)}")
        r = revoke(okey, opem, o2serial, "cessationOfOperation")
        if r.status_code != 200:
            die(f"could not revoke the second operator: {r.status_code} {r.text}")
        r = revoke(o2key, o2pem, vserial)
        ok(f"a revoked operator's request is refused ({r.status_code})") \
            if r.status_code == 400 else die(f"expected 400, got {r.status_code} {r.text}")
        _, crl = fetch_crl()
        ok("the would-be victim is not listed") if not listed(crl, vserial) \
            else die("victim was revoked by a revoked operator")

        print("G7: the list cannot be altered in transit")
        token, _ = fetch_crl()
        head, payload, sig = token.split(".")
        forged = payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1]
        try:
            jwt.decode(".".join([head, forged, sig]), anchor_pem(), algorithms=["RS256"])
            die("a tampered CRL verified")
        except jwt.InvalidTokenError as e:
            ok(f"a tampered CRL fails verification ({type(e).__name__})")

        print("G8: the appliance adopts the CA's list through its own poll")
        wkey, wpem, _, wserial = ra_identity(f"owner-{secrets.token_hex(3)}")
        requests.post(f"{VPP}/enroll", json={"certificate": wpem}, verify=CA_FILE)
        ven = onboard(wkey, wpem, write_pair("owner", wkey, wpem))
        body = requests.post(f"{APP}/poll").json()
        _, crl = fetch_crl()
        out = body.get("crl") or {}
        ok(f"appliance adopted CRL #{out.get('crl_number')} ({out.get('status')}, "
           f"{out.get('revoked')} revoked)") \
            if out.get("status") in ("stored", "current") and out.get("crl_number") == crl["crl_number"] \
            else die(f"appliance did not adopt the list: {out}")
        status = requests.get(f"{APP}/status").json()
        ok("the number is persisted on the device") if status["crl_number"] == crl["crl_number"] \
            else die(f"status reports CRL #{status['crl_number']}")
        current_number = crl["crl_number"]

        print("G9: a rolled-back list relayed by the VPP is refused by the appliance itself")
        plant_crl(stale_token)
        out = requests.post(f"{APP}/poll").json().get("crl") or {}
        ok(f"appliance refused the rollback: {out.get('reason')}") \
            if out.get("status") == "refused" and "stale" in out.get("reason", "") \
            else die(f"rollback accepted: {out}")
        status = requests.get(f"{APP}/status").json()
        ok(f"appliance keeps its newer list (#{status['crl_number']})") \
            if status["crl_number"] == current_number else die("appliance lost its list")

        print("G10: a list signed outside the CA is refused")
        plant_crl(forged_crl(current_number + 10))
        out = requests.post(f"{APP}/poll").json().get("crl") or {}
        ok(f"appliance refused the forged list: {out.get('reason', '')[:60]}") \
            if out.get("status") == "refused" and "not signed" in out.get("reason", "") \
            else die(f"forged list accepted: {out}")
        clear_crl()

        print("G11: with its list expired and no fresh one, the appliance stops acting")
        cfg = json.loads(CONFIG.read_text())
        cfg["crl_next_update"] = (datetime.datetime.now(datetime.timezone.utc)
                                  - datetime.timedelta(hours=1)).isoformat()
        CONFIG.write_text(json.dumps(cfg, indent=2) + "\n")
        plant_crl(stale_token)
        act_a = f"act-expired-{secrets.token_hex(4)}"
        inject_activation(ven, act_a)
        body = requests.post(f"{APP}/poll").json()
        refusal = next((x for x in body.get("refused", []) if x["activation_id"] == act_a), None)
        ok(f"activation refused: {refusal['reason'][:58]}") \
            if refusal and "expired" in refusal["reason"] \
            else die(f"activation not refused on an expired list: {body}")
        clear_crl()
        body = requests.post(f"{APP}/poll").json()
        status = requests.get(f"{APP}/status").json()
        fresh = datetime.datetime.fromisoformat(status["crl_next_update"])
        ok("a fresh list from the CA restores operation") \
            if (body.get("crl") or {}).get("status") in ("stored", "current") \
            and fresh > datetime.datetime.now(datetime.timezone.utc) \
            else die(f"list not refreshed: {body.get('crl')}")

        print("G12: once the owner is revoked, the appliance refuses the owner's calendar and activations")
        r = revoke(okey, opem, wserial, "keyCompromise")
        if r.status_code != 200:
            die(f"could not revoke the owner: {r.status_code} {r.text}")
        act_b = f"act-revoked-owner-{secrets.token_hex(4)}"
        inject_activation(ven, act_b)
        body = requests.post(f"{APP}/poll").json()
        cal = body.get("calendar") or {}
        ok(f"owner's calendar refused: {cal.get('reason')}") \
            if cal.get("status") == "refused" and "revoked" in cal.get("reason", "") \
            else die(f"calendar from a revoked owner accepted: {cal}")
        refusal = next((x for x in body.get("refused", []) if x["activation_id"] == act_b), None)
        ok(f"activation refused: {refusal['reason']}") \
            if refusal and "owner certificate is revoked" in refusal["reason"] \
            else die(f"activation accepted for a revoked owner: {body}")
        with sqlite3.connect(str(DB_FILE)) as c:
            c.execute("DELETE FROM activations WHERE activation_id IN (?, ?)", (act_a, act_b))

        print(f"\nREVOCATION COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
