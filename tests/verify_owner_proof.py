import base64
import secrets
import shutil
import sqlite3
import sys
import tempfile
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

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="ownerproof_"))


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1)


def enrolled_user(name: str):
    """Get a certificate from the RA and enroll it at the VPP; return (cert, key)
    file paths usable as a mutual-TLS client identity."""
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


def pair_appliance(key, cert_pem: str) -> dict:
    """Run local pairing as this user and return the appliance's response."""
    requests.post(f"{APP}/factory-reset")
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    token = jwt.encode({
        "vpp_url": VPP, "vpp_mtls_url": MTLS,
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text(),
    }, key_pem, algorithm="RS256",
        headers={"x5c": [x5c], "typ": "application/pairing+json"})
    r = requests.post(f"{APP}/pair", json={"jws": token})
    if not r.ok:
        die(f"/pair -> {r.status_code} {r.text}")
    return r.json()


def forged_proof(owner_subject: str, power: int) -> str:
    """A proof correctly signed by the appliance's certified key but declaring a
    different nominal power (simulates a compromised appliance)."""
    key = serialization.load_pem_private_key((CERTS / "VEN.key").read_bytes(), None)
    cert = x509.load_pem_x509_certificate((CERTS / "VEN.crt").read_bytes())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode({
        "ven": cert.subject.rfc4514_string(), "owner": owner_subject,
        "P": power, "max": 120, "rec": 30,
    }, key_pem, algorithm="RS256",
        headers={"x5c": [x5c], "typ": "application/owner-proof+json"})


def main():
    try:
        user = f"user-{secrets.token_hex(3)}"
        ukey, ucert_pem, uclient = enrolled_user(user)
        user_subject = x509.load_pem_x509_certificate(
            ucert_pem.encode()).subject.rfc4514_string()
        paired = pair_appliance(ukey, ucert_pem)
        proof = paired["owner_proof"]

        print("G1: the owner forwards the proof over mutual TLS")
        r = requests.post(f"{MTLS}/appliances/owner-proof",
                          json={"owner_proof": proof}, cert=uclient, verify=CA_FILE)
        if r.status_code != 200:
            die(f"expected 200, got {r.status_code} {r.text}")
        body = r.json()
        ok(f"appliance bound to its owner: {body['ven']} -> {body['owner']}") \
            if body["owner"] == user_subject else die(f"bound to {body['owner']}")
        ok(f"parameters recorded: {body['parameters']}") \
            if body["parameters"] == {"P": 2000, "max": 120, "rec": 30} \
            else die(f"unexpected parameters {body['parameters']}")

        print("G2: the VPP persisted the ownership relation")
        row = sqlite3.connect(str(DB_FILE)).execute(
            """SELECT owner, nominal_power, max_curtail, recovery, cert_pem
               FROM appliances WHERE ven_subject=?""", (body["ven"],)).fetchone()
        if not row:
            die("ownership not persisted")
        ok(f"stored owner={row[0]} P={row[1]} max={row[2]} rec={row[3]}") \
            if row[0] == user_subject else die(f"stored owner {row[0]}")
        ok("appliance certificate stored (verifies its future messages)") \
            if "BEGIN CERTIFICATE" in row[4] else die("certificate not stored")

        print("G3: a different user cannot claim the appliance")
        _k2, _c2, other = enrolled_user(f"user-{secrets.token_hex(3)}")
        r = requests.post(f"{MTLS}/appliances/owner-proof",
                          json={"owner_proof": proof}, cert=other, verify=CA_FILE)
        ok("proof forwarded by another user rejected (403)") \
            if r.status_code == 403 else die(f"expected 403, got {r.status_code}")

        print("G4: the certified power cannot be over-declared")
        r = requests.post(f"{MTLS}/appliances/owner-proof",
                          json={"owner_proof": forged_proof(user_subject, 9999)},
                          cert=uclient, verify=CA_FILE)
        ok("proof over-declaring P rejected, though correctly signed") \
            if r.status_code in (400, 403) else die(f"expected 400/403, got {r.status_code}")

        print("G5: a tampered proof is rejected")
        h, p, s = proof.split(".")
        bad = f"{h}.{p}.{('A' if s[0] != 'A' else 'B') + s[1:]}"
        r = requests.post(f"{MTLS}/appliances/owner-proof",
                          json={"owner_proof": bad}, cert=uclient, verify=CA_FILE)
        ok("tampered proof rejected") if r.status_code in (400, 403) \
            else die(f"expected 400/403, got {r.status_code}")

        print(f"\nOWNER PROOF COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
