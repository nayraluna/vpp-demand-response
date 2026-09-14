import importlib.util
import sys
from pathlib import Path

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certs"
CA_FILE = str(CERTS / "CA.crt")
VPP = "https://127.0.0.1:8080"
MAN = "https://127.0.0.1:8081"

sys.path.insert(0, str(ROOT / "appliance"))
import hsm  # noqa: E402

# The VPP no longer exposes a signing endpoint (it would be an unauthenticated
# signing oracle), so its signing identity is exercised in-process. Loaded by
# file path because both the appliance and the VPP have an `app` package.
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


def chains_to_ca(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    try:
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False


def main():
    ca = x509.load_pem_x509_certificate(Path(CA_FILE).read_bytes())

    print("G1: PKI chain")
    for name in ["vpp", "server", "VEN"]:
        cert = x509.load_pem_x509_certificate((CERTS / f"{name}.crt").read_bytes())
        if chains_to_ca(cert, ca):
            ok(f"{name}.crt issued by the RA ({cert.subject.rfc4514_string()})")
        else:
            die(f"{name}.crt does NOT chain to the RA")

    print("G2: VPP over TLS")
    r = requests.get(f"{VPP}/ping", verify=CA_FILE)
    ok(f"/ping -> {r.json()}") if r.ok else die(r.text)
    try:
        requests.get(f"{VPP}/ping", verify=True)
        die("VPP certificate accepted by the public trust store")
    except requests.exceptions.SSLError:
        ok("VPP rejected without our CA (as expected)")
    # Signing identity: in-process round trip (that the RUNNING server holds
    # vpp.key is what the mutual-TLS gate proves at the handshake).
    vpp_crypto.initialize()
    vpp_cert = x509.load_pem_x509_certificate(vpp_crypto.certificate_pem().encode())
    if chains_to_ca(vpp_cert, ca):
        ok(f"VPP signing certificate chains to RA ({vpp_cert.subject.rfc4514_string()})")
    else:
        die("VPP signing certificate not issued by our RA")
    sig = bytes.fromhex(vpp_crypto.sign("hello world"))
    try:
        vpp_cert.public_key().verify(sig, b"hello world", padding.PKCS1v15(), hashes.SHA256())
        ok("VPP signature over 'hello world' verifies")
    except InvalidSignature:
        die("VPP signature did not verify")
    try:
        vpp_cert.public_key().verify(sig, b"hello worle", padding.PKCS1v15(), hashes.SHA256())
        die("tampered message verified (broken logic)")
    except InvalidSignature:
        ok("tampered message rejected")

    print("G3: Manufacturer over TLS")
    r = requests.get(f"{MAN}/ping", verify=CA_FILE)
    ok(f"/ping -> {r.json()}") if r.ok else die(r.text)
    r = requests.get(f"{MAN}/ra/certificate", verify=CA_FILE)
    served = x509.load_pem_x509_certificate(r.json()["certificate"].encode())
    if served.fingerprint(hashes.SHA256()) == ca.fingerprint(hashes.SHA256()):
        ok("RA distributes the correct trust anchor (CA.crt)")
    else:
        die("RA served a different CA certificate")

    print("G4: Appliance (VEN) identity")
    hsm.initialize()
    ok(f"software HSM loaded VEN identity ({hsm.subject()})")
    ven_cert = x509.load_pem_x509_certificate(hsm.certificate_pem().encode())
    if chains_to_ca(ven_cert, ca):
        ok("VEN certificate chains to RA")
    else:
        die("VEN certificate not issued by our RA")
    msg = "ven-0001|hello world"
    sig = bytes.fromhex(hsm.sign(msg))
    try:
        ven_cert.public_key().verify(sig, msg.encode(), padding.PKCS1v15(), hashes.SHA256())
        ok("VEN signature verifies with certified public key")
    except InvalidSignature:
        die("VEN signature did not verify")
    try:
        ven_cert.public_key().verify(sig, b"ven-0001|hello w0rld", padding.PKCS1v15(), hashes.SHA256())
        die("tampered VEN message verified (broken logic)")
    except InvalidSignature:
        ok("tampered VEN message rejected")

    print(f"\nSETUP PHASE COMPLETE: {passed} checks passed, {failed} failed.")


if __name__ == "__main__":
    main()
