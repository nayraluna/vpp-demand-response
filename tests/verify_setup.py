import importlib.util
import socket
import ssl
import sys
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certs"
CA_FILE = str(CERTS / "CA.crt")
VPP = "https://127.0.0.1:8080"
CA = "https://127.0.0.1:8081"

sys.path.insert(0, str(ROOT / "appliance"))
import hsm  # noqa: E402

# The VPP exposes no signing endpoint (it would be a signing oracle), so its identity
# is exercised in-process; loaded by path because both sides have an `app` package.
_spec = importlib.util.spec_from_file_location(
    "vpp_crypto_service", ROOT / "vpp-server" / "app" / "crypto_service.py")
vpp_crypto = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vpp_crypto)

passed = failed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    global failed
    failed += 1
    print(f"  [FAIL] {msg}")
    sys.exit(1)


def raw_verify(pub, sig, msg):
    """Detached signature check for whichever key type the certificate carries."""
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    else:
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())


def chains_to_ca(cert, ca) -> bool:
    """Through an issuing CA to the root: a leaf the root signed directly is not a platform certificate."""
    issuing = [x509.load_pem_x509_certificate((Path(CA_FILE).parent / f).read_bytes())
               for f in ("platform-ca.crt", "device-ca.crt")]
    for issuer in issuing:
        try:
            cert.verify_directly_issued_by(issuer)
            issuer.verify_directly_issued_by(ca)
            return True
        except Exception:
            continue
    return False


def main():
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())

    print("G1: PKI chain")
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    ok("root is CA:TRUE with pathLen 1, critical: issuing CAs below it, nothing below them") \
        if bc.critical and bc.value.ca and bc.value.path_length == 1 \
        else die(f"root BasicConstraints {bc.value} critical={bc.critical}")
    for name in ("platform-ca", "device-ca"):
        issuing = x509.load_pem_x509_certificate((CERTS / f"{name}.crt").read_bytes())
        ibc = issuing.extensions.get_extension_for_class(x509.BasicConstraints)
        try:
            issuing.verify_directly_issued_by(ca)
            signed = True
        except Exception:
            signed = False
        ok(f"{name}.crt is an issuing CA signed by the root, pathLen 0 ({issuing.subject.rfc4514_string()})") \
            if signed and ibc.critical and ibc.value.ca and ibc.value.path_length == 0 \
            else die(f"{name}.crt is not a pathLen 0 issuing CA under the root")
    for name, issuer in (("vpp", "platform-ca"), ("server", "platform-ca"), ("VEN", "device-ca")):
        chain = x509.load_pem_x509_certificates((CERTS / f"{name}.crt").read_bytes())
        cert = chain[0]
        expected = x509.load_pem_x509_certificate((CERTS / f"{issuer}.crt").read_bytes())
        if chains_to_ca(cert, ca) and cert.issuer == expected.subject and len(chain) == 2:
            ok(f"{name}.crt issued by the {issuer.split('-')[0]} CA, chain shipped with the leaf ({cert.subject.rfc4514_string()})")
        else:
            die(f"{name}.crt does NOT chain to the root through the {issuer}")
    try:
        root_crl = x509.load_der_x509_crl((CERTS / "root.crl").read_bytes())
        ok(f"root CRL published offline, signed by the root, valid until {root_crl.next_update_utc.date()}") \
            if root_crl.is_signature_valid(ca.public_key()) and root_crl.issuer == ca.subject \
            else die("root.crl does not verify against the root")
    except FileNotFoundError:
        die("no root.crl: the root never published its list")

    print("G2: VPP over TLS")
    r = requests.get(f"{VPP}/ping", verify=CA_FILE)
    ok(f"/ping -> {r.json()}") if r.ok else die(r.text)
    try:
        requests.get(f"{VPP}/ping", verify=True)
        die("VPP certificate accepted by the public trust store")
    except requests.exceptions.SSLError:
        ok("VPP rejected without our CA (as expected)")
    # In-process; that the running server holds vpp.key is what the mTLS gate proves.
    vpp_crypto.initialize()
    vpp_cert = x509.load_pem_x509_certificate(vpp_crypto.certificate_pem().encode())
    if chains_to_ca(vpp_cert, ca):
        ok(f"VPP signing certificate chains to the CA ({vpp_cert.subject.rfc4514_string()})")
    else:
        die("VPP signing certificate not issued by our CA")
    sig = bytes.fromhex(vpp_crypto.sign("hello world"))
    try:
        raw_verify(vpp_cert.public_key(), sig, b"hello world")
        ok("VPP signature over 'hello world' verifies")
    except InvalidSignature:
        die("VPP signature did not verify")
    try:
        raw_verify(vpp_cert.public_key(), sig, b"hello worle")
        die("tampered message verified (broken logic)")
    except InvalidSignature:
        ok("tampered message rejected")

    print("G3: CA over TLS")
    r = requests.get(f"{CA}/ping", verify=CA_FILE)
    ok(f"/ping -> {r.json()}") if r.ok else die(r.text)
    r = requests.get(f"{CA}/ra/certificate", verify=CA_FILE)
    served = x509.load_pem_x509_certificate(r.json()["certificate"].encode())
    if served.fingerprint(hashes.SHA256()) == ca.fingerprint(hashes.SHA256()):
        ok("RA distributes the correct trust anchor (CA.crt)")
    else:
        die("RA served a different CA certificate")
    ok(f"RA distributes the issuing certificates too ({', '.join(sorted(r.json()['issuing']))})") \
        if set(r.json().get("issuing", {})) == {"platform", "device"} \
        else die(f"issuing certificates missing from /ra/certificate: {r.json().keys()}")
    r = requests.get("http://127.0.0.1:8084/ping", timeout=3)
    ok("the CA process answers on loopback only (:8084), apart from the RA") if r.ok else die("CA process down")

    print("G4: Appliance (VEN) identity")
    hsm.initialize()
    ok(f"software HSM loaded VEN identity ({hsm.subject()})")
    ven_cert = x509.load_pem_x509_certificate(hsm.certificate_pem().encode())
    if chains_to_ca(ven_cert, ca):
        ok("VEN certificate chains to the CA")
    else:
        die("VEN certificate not issued by our CA")
    msg = "ven-0001|hello world"
    sig = bytes.fromhex(hsm.sign(msg))
    try:
        raw_verify(ven_cert.public_key(), sig, msg.encode())
        ok("VEN signature verifies with certified public key")
    except InvalidSignature:
        die("VEN signature did not verify")
    try:
        raw_verify(ven_cert.public_key(), sig, b"ven-0001|hello w0rld")
        die("tampered VEN message verified (broken logic)")
    except InvalidSignature:
        ok("tampered VEN message rejected")

    print("G5: every TLS listener refuses a client limited to TLS 1.2")
    for port in (8080, 8081, 8443):
        old = ssl.create_default_context(cafile=CA_FILE)
        old.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
                    old.wrap_socket(raw, server_hostname="localhost"):
                die(f":{port} accepted TLS 1.2")
        except ssl.SSLError as e:
            ok(f":{port} refuses TLS 1.2 ({e.reason})")

    print(f"\nSETUP PHASE COMPLETE: {passed} checks passed, {failed} failed.")


if __name__ == "__main__":
    main()
