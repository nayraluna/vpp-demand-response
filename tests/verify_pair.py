import base64
import datetime
import secrets
import sys
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
MAN = "https://127.0.0.1:8081"
APP = "http://127.0.0.1:8082"  # local pairing channel

passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    sys.exit(1)


def ra_cert(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .sign(key, hashes.SHA256()))
    r = requests.post(f"{MAN}/ra/issue",
                      json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
                      verify=CA_FILE)
    if not r.ok:
        die(f"RA /ra/issue -> {r.status_code} {r.text}")
    return key, r.json()["certificate"]


def self_signed(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def make_jws(key, cert_pem: str, payload: dict) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    x5c = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return jwt.encode(payload, key_pem, algorithm="RS256",
                      headers={"x5c": [x5c], "typ": "application/pairing+json"})


def bundle() -> dict:
    """What the app sends: how to reach the VPP. NOT the appliance parameters -
    those are device properties the appliance itself reports back."""
    return {
        "vpp_url": "https://127.0.0.1:8080",
        "vpp_mtls_url": "https://127.0.0.1:8443",
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
        "cert_ra": (CERTS / "CA.crt").read_text(),
    }


def main():
    requests.post(f"{APP}/factory-reset")
    r = requests.get(f"{APP}/ping")
    ok("appliance in pairing mode (state 0)") if r.json()["state"] == 0 \
        else die(f"expected state 0, got {r.json()}")

    okey, ocert = ra_cert(f"user-{secrets.token_hex(3)}")
    token = make_jws(okey, ocert, bundle())

    print("G1: bad bundles are refused while still in pairing mode")
    h, p, s = token.split(".")
    bad = f"{h}.{p}.{('A' if s[0] != 'A' else 'B') + s[1:]}"
    r = requests.post(f"{APP}/pair", json={"jws": bad})
    ok("tampered bundle rejected (400)") if r.status_code == 400 \
        else die(f"expected 400, got {r.status_code}")

    skey, scert = self_signed("rogue")
    r = requests.post(f"{APP}/pair", json={"jws": make_jws(skey, scert, bundle())})
    ok("owner not certified by the RA rejected (400)") if r.status_code == 400 \
        else die(f"expected 400, got {r.status_code}")

    print("G2: a correct bundle pairs the appliance")
    r = requests.post(f"{APP}/pair", json={"jws": token})
    if not r.ok:
        die(f"/pair -> {r.status_code} {r.text}")
    body = r.json()
    params = body["parameters"]
    ok(f"paired with owner {body['owner']}")
    ok(f"appliance reported its parameters: {params}") \
        if params == {"P": 2000, "max": 120, "rec": 30} \
        else die(f"unexpected parameters: {params}")

    print("G3: the appliance returns an owner proof signed by its HSM")
    proof = body.get("owner_proof")
    if not proof:
        die("no owner proof returned")
    header = jwt.get_unverified_header(proof)
    ok("owner proof is a JWS carrying the VEN certificate (x5c)") \
        if header.get("x5c") else die("owner proof has no x5c")
    ven_cert = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    ven_pub = ven_cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    payload = jwt.decode(proof, ven_pub, algorithms=["RS256"])
    ok(f"owner proof binds {payload['ven']} to {payload['owner']}") \
        if payload["owner"] == body["owner"] else die("proof names a different owner")
    ok(f"declared power P={payload['P']} matches the certificate (OU=P=...)") \
        if f"P={payload['P']}" in ven_cert.subject.rfc4514_string() \
        else die("declared power is not the certified one")

    print("G4: state and configuration persisted")
    cfg = requests.get(f"{APP}/config").json()
    ok("appliance left pairing mode (state 1)") if cfg["state"] == 1 \
        else die(f"expected state 1, got {cfg['state']}")
    ok(f"VPP address stored: {cfg['vpp_url']}") if cfg["vpp_url"] else die("no vpp_url")

    r = requests.post(f"{APP}/pair", json={"jws": token})
    ok("re-pairing a configured appliance refused (409)") if r.status_code == 409 \
        else die(f"expected 409, got {r.status_code}")

    print(f"\nLOCAL PAIRING COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
