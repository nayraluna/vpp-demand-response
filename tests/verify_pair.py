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
CA = "https://127.0.0.1:8081"
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
    r = requests.post(f"{CA}/ra/issue",
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


def fake_platform():
    """Another root with a user and a VPP under it: internally consistent, worthless to the device."""
    def make(subject, issuer_name, issuer_key, key, ca):
        now = datetime.datetime.now(datetime.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        return b.sign(issuer_key, hashes.SHA256())
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Platform Root")])
    root = make(root_name, root_name, root_key, root_key, True)
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user = make(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-user")]),
                root_name, root_key, user_key, False)
    vpp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vpp = make(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-vpp")]),
               root_name, root_key, vpp_key, False)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    return pem(root), user_key, pem(user), pem(vpp)


def expired_from_ca(cn: str):
    """Minted with the CA key: a fixture the CA itself would never issue."""
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())
    ca_key = serialization.load_pem_private_key((Path(CA_FILE).parent / "CA.key").read_bytes(), None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=2))
        .not_valid_after(now - datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def bundle() -> dict:
    """How to reach the VPP; the appliance reports its own parameters."""
    return {
        "vpp_url": "https://127.0.0.1:8080",
        "vpp_mtls_url": "https://127.0.0.1:8443",
        "cert_vpp": (CERTS / "vpp.crt").read_text(),
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
    ok("owner not certified by the CA rejected (400)") if r.status_code == 400 \
        else die(f"expected 400, got {r.status_code}")

    # Consistent under the attacker's own root, offered as cert_ra: the device
    # trusts only the root it was provisioned with and ignores the field.
    froot, fkey, fuser, fvpp = fake_platform()
    fake = {**bundle(), "cert_ra": froot, "cert_vpp": fvpp}
    r = requests.post(f"{APP}/pair", json={"jws": make_jws(fkey, fuser, fake)})
    ok(f"a bundle vouched for only by its own root is refused (400): {r.json().get('detail', '')[:52]}") \
        if r.status_code == 400 else die(f"fake platform accepted: {r.status_code} {r.text}")
    r = requests.get(f"{APP}/ping")
    ok("appliance still unpaired after the attempt") if r.json()["state"] == 0 \
        else die("the fake platform paired the appliance")

    ekey, ecert = expired_from_ca(f"expired-{secrets.token_hex(3)}")
    r = requests.post(f"{APP}/pair", json={"jws": make_jws(ekey, ecert, bundle())})
    ok(f"expired owner certificate rejected (400): {r.json().get('detail', '')}") \
        if r.status_code == 400 and "expired" in r.text \
        else die(f"expected 400 expired, got {r.status_code} {r.text}")

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
