import datetime
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

import requests
from requests.exceptions import ConnectionError, SSLError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent
CA_FILE = str(ROOT / "certs" / "CA.crt")
VPP = "https://127.0.0.1:8080"
CA = "https://127.0.0.1:8081"
MTLS = "https://127.0.0.1:8443"

passed = 0
tmp = Path(tempfile.mkdtemp(prefix="mtls_gate_"))


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


def below_intermediate():
    """A client certificate under a CA certificate the root really signed. The CA key is read
    only to mint this fixture: the CA never issues CA:TRUE, which is what pathLen 0 backs up."""
    root = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())
    root_key = serialization.load_pem_private_key((Path(CA_FILE).parent / "CA.key").read_bytes(), None)
    now = datetime.datetime.now(datetime.timezone.utc)
    ku = dict(content_commitment=False, key_encipherment=False, data_encipherment=False,
              key_agreement=False, encipher_only=False, decipher_only=False)
    ikey = ec.generate_private_key(ec.SECP256R1())
    iname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unplanned Issuing CA")])
    inter = (x509.CertificateBuilder().subject_name(iname).issuer_name(root.subject)
             .public_key(ikey.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(minutes=5))
             .not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=False, key_cert_sign=True, crl_sign=True, **ku),
                            critical=True)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(ikey.public_key()), critical=False)
             .sign(root_key, hashes.SHA256()))
    lkey = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"below-{secrets.token_hex(3)}")]))
            .issuer_name(iname).public_key(lkey.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, **ku),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False)
            .sign(ikey, hashes.SHA256()))
    chain = leaf.public_bytes(serialization.Encoding.PEM) + inter.public_bytes(serialization.Encoding.PEM)
    return write_pair("below", lkey, chain.decode())


def main():
    try:
        print("G1: enrolled user gets an authenticated mutual-TLS session")
        key, cert = ra_cert(f"user-{secrets.token_hex(3)}")
        requests.post(f"{VPP}/enroll", json={"certificate": cert}, verify=CA_FILE)
        cf, kf = write_pair("user", key, cert)
        r = requests.get(f"{MTLS}/session", cert=(cf, kf), verify=CA_FILE)
        if r.status_code == 200 and r.json().get("authenticated"):
            ok(f"authenticated over mTLS as {r.json()['user']}")
        else:
            die(f"expected authenticated session, got {r.status_code} {r.text}")

        # Under TLS 1.3 the server rejects the client certificate after its own flight,
        # so the client sees either an SSLError or a closed connection.
        print("G2: a client WITHOUT a certificate is rejected at the handshake")
        try:
            requests.get(f"{MTLS}/session", verify=CA_FILE)
            die("connection without a client cert was accepted")
        except (SSLError, ConnectionError) as e:
            ok(f"no-certificate client rejected ({type(e).__name__})")

        print("G3: a NON-RA certificate is rejected at the handshake")
        sk, scert = self_signed("rogue")
        scf, skf = write_pair("rogue", sk, scert)
        try:
            requests.get(f"{MTLS}/session", cert=(scf, skf), verify=CA_FILE)
            die("self-signed client cert was accepted")
        except (SSLError, ConnectionError) as e:
            ok(f"self-signed (foreign) client cert rejected ({type(e).__name__})")

        print("G4: an RA cert that was never enrolled is not authorized")
        gkey, gcert = ra_cert(f"ghost-{secrets.token_hex(3)}")
        gcf, gkf = write_pair("ghost", gkey, gcert)
        r = requests.get(f"{MTLS}/session", cert=(gcf, gkf), verify=CA_FILE)
        ok("valid platform cert but no account -> 403") if r.status_code == 403 \
            else die(f"expected 403, got {r.status_code} {r.text}")

        print("G5: a certificate below an intermediate is refused at the handshake (root pathLen 0)")
        ccf, ckf = below_intermediate()
        try:
            r = requests.get(f"{MTLS}/session", cert=(ccf, ckf), verify=CA_FILE)
            die(f"a chain through an intermediate passed the handshake ({r.status_code})")
        except (SSLError, ConnectionError) as e:
            ok(f"leaf -> intermediate -> root refused by the TLS layer ({type(e).__name__})")

        print(f"\nMUTUAL TLS COMPLETE: {passed} checks passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
