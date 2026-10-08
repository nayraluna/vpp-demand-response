import base64
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
import datetime
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
VPP = "https://127.0.0.1:8080"
CA = "https://127.0.0.1:8081"
MTLS = "https://127.0.0.1:8443"
APP = "http://127.0.0.1:8082"
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="renewal_gate_"))


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


def csr_for(key, subject: x509.Name) -> str:
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def ra_identity(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    r = requests.post(f"{CA}/ra/issue", json={"csr": csr_for(key, subject)}, verify=CA_FILE)
    if not r.ok:
        die(f"/ra/issue -> {r.status_code} {r.text}")
    pem = r.json()["certificate"]
    requests.post(f"{VPP}/enroll", json={"certificate": pem}, verify=CA_FILE)
    cert = x509.load_pem_x509_certificate(pem.encode())
    return key, pem, cert, format(cert.serial_number, "x")


def sign_as(key, cert_pem: str, payload: dict, typ: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256", headers={"x5c": [x5c], "typ": typ})


def renew(key, cert_pem: str, new_key, subject: x509.Name):
    """Signed with the CURRENT credential, carrying a CSR for the new key."""
    token = sign_as(key, cert_pem, {"csr": csr_for(new_key, subject)},
                    "application/renewal-request+json")
    return requests.post(f"{CA}/ra/renew", json={"request": token}, verify=CA_FILE)


def fetch_crl() -> dict:
    r = requests.get(f"{CA}/ra/crl", verify=CA_FILE)
    r.raise_for_status()
    anchor = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes()).public_key()
    return jwt.decode(r.json()["crl"], anchor.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        algorithms=["RS256"])


def crl_entry(crl: dict, serial: str) -> dict | None:
    return next((e for e in crl["revoked"] if e["serial"] == serial), None)


def declare(key, cert_pem: str, client, ven: str) -> None:
    calendar = {d: "1" * 48 for d in DAYS}
    r = requests.post(f"{MTLS}/availability",
                      json={"ven": ven, "jws": sign_as(
                          key, cert_pem, {"slots": calendar, "version": int(time.time() * 1000)},
                          "application/availability+json")},
                      cert=client, verify=CA_FILE)
    if not r.ok:
        die(f"/availability -> {r.status_code} {r.text}")


def onboard(key, cert_pem: str, client) -> str:
    requests.post(f"{APP}/factory-reset")
    bundle = sign_as(key, cert_pem, {
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text()}, "application/pairing+json")
    proof = requests.post(f"{APP}/pair", json={"jws": bundle}).json()["owner_proof"]
    ven = requests.post(f"{MTLS}/appliances/owner-proof", json={"owner_proof": proof},
                        cert=client, verify=CA_FILE).json()["ven"]
    declare(key, cert_pem, client, ven)
    return ven


def inject_activation(ven: str, act_id: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    slot = now.hour * 2 + now.minute // 30
    with sqlite3.connect(str(DB_FILE)) as c:
        c.execute(
            """INSERT INTO activations(activation_id, ven_subject, day, slot_start, slot_end,
                   action, issued_at, ends_at, delivered_at)
               VALUES(?,?,?,?,?,'reduce',?,NULL,NULL)""",
            (act_id, ven, DAYS[now.weekday()], slot, min(slot + 1, 48), now.isoformat()))


def main():
    try:
        print("G1: a user renews with a new key and keeps the same identity")
        key, pem, cert, serial = ra_identity(f"user-{secrets.token_hex(3)}")
        client = write_pair("old", key, pem)
        r = requests.get(f"{MTLS}/session", cert=client, verify=CA_FILE)
        if r.status_code != 200:
            die(f"fresh user cannot authenticate: {r.status_code} {r.text}")
        new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        r = renew(key, pem, new_key, cert.subject)
        body = r.json()
        if r.status_code != 200:
            die(f"renewal refused: {r.status_code} {r.text}")
        new_pem = body["certificate"]
        new_cert = x509.load_pem_x509_certificate(new_pem.encode())
        new_serial = format(new_cert.serial_number, "x")
        ok(f"renewed: same subject {new_cert.subject.rfc4514_string()}") \
            if new_cert.subject == cert.subject else die("subject changed on renewal")
        ok(f"new serial {new_serial[:12]}..., old {serial[:12]}... superseded") \
            if new_serial != serial and body["superseded"] == serial \
            else die(f"unexpected serials: {body}")

        print("G2: the new credential works at once, the old one is dead")
        new_client = write_pair("new", new_key, new_pem)
        r = requests.get(f"{MTLS}/session", cert=new_client, verify=CA_FILE)
        ok("new certificate authenticates over mTLS without re-enrolling") \
            if r.status_code == 200 else die(f"new certificate refused: {r.status_code} {r.text}")
        r = requests.get(f"{MTLS}/session", cert=client, verify=CA_FILE)
        ok(f"old certificate refused ({r.status_code}: {r.json().get('error')})") \
            if r.status_code == 403 else die(f"old certificate still accepted: {r.status_code}")
        entry = crl_entry(fetch_crl(), serial)
        ok(f"old serial listed in the CRL as {entry['reason']}") \
            if entry and entry["reason"] == "superseded" else die(f"old serial not superseded: {entry}")

        print("G3: renewal must change the key")
        r = renew(new_key, new_pem, new_key, cert.subject)
        ok(f"re-using the current key is refused ({r.status_code})") \
            if r.status_code == 409 else die(f"expected 409, got {r.status_code} {r.text}")

        print("G4: renewal cannot change who you are")
        other = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "someone-else"),
                           x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "role=operator")])
        r = renew(new_key, new_pem, rsa.generate_private_key(public_exponent=65537, key_size=2048), other)
        ok(f"a CSR with another subject is refused ({r.status_code}: {r.json()['detail']})") \
            if r.status_code == 400 and "subject" in r.json()["detail"] \
            else die(f"expected 400, got {r.status_code} {r.text}")

        print("G5: a revoked credential cannot renew itself")
        r = renew(key, pem, rsa.generate_private_key(public_exponent=65537, key_size=2048), cert.subject)
        ok(f"the superseded certificate is refused ({r.status_code}: {r.json()['detail']})") \
            if r.status_code == 400 and "revoked" in r.json()["detail"] \
            else die(f"expected 400, got {r.status_code} {r.text}")

        print("G6: the appliance follows its owner through a renewal")
        wkey, wpem, wcert, wserial = ra_identity(f"owner-{secrets.token_hex(3)}")
        wclient = write_pair("owner", wkey, wpem)
        ven = onboard(wkey, wpem, wclient)
        requests.post(f"{APP}/poll")
        status = requests.get(f"{APP}/status").json()
        ok(f"appliance bound to the owner's certificate {wserial[:12]}...") \
            if status["owner_serial"] == wserial else die(f"owner_serial is {status['owner_serial']}")

        wkey2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        r = renew(wkey, wpem, wkey2, wcert.subject)
        if r.status_code != 200:
            die(f"owner renewal refused: {r.status_code} {r.text}")
        wpem2 = r.json()["certificate"]
        wserial2 = format(x509.load_pem_x509_certificate(wpem2.encode()).serial_number, "x")
        act_a = f"act-renew-{secrets.token_hex(4)}"
        inject_activation(ven, act_a)
        body = requests.post(f"{APP}/poll").json()
        refusal = next((x for x in body.get("refused", []) if x["activation_id"] == act_a), None)
        ok("until the owner re-declares, the appliance refuses: "
           + (refusal["reason"] if refusal else "")) \
            if refusal and "owner certificate is revoked" in refusal["reason"] \
            else die(f"expected refusal for the superseded owner: {body}")

        wclient2 = write_pair("owner2", wkey2, wpem2)
        declare(wkey2, wpem2, wclient2, ven)
        act_b = f"act-renewed-{secrets.token_hex(4)}"
        inject_activation(ven, act_b)
        body = requests.post(f"{APP}/poll").json()
        status = requests.get(f"{APP}/status").json()
        ok(f"after re-declaring with the new key, the appliance rebinds to {wserial2[:12]}...") \
            if status["owner_serial"] == wserial2 else die(f"owner_serial still {status['owner_serial']}")
        executed = any(x["activation_id"] == act_b for x in body.get("executed", []))
        refusal = next((x for x in body.get("refused", []) if x["activation_id"] == act_b), None)
        ok("and acts again on the owner's behalf") if executed \
            else die(f"activation still refused: {refusal}")
        with sqlite3.connect(str(DB_FILE)) as c:
            c.execute("DELETE FROM activations WHERE activation_id IN (?, ?)", (act_a, act_b))

        print(f"\nRENEWAL COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
