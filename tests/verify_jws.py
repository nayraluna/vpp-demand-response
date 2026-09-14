import base64
import json
import sys
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parent.parent
CERTS = ROOT / "certs"
sys.path.insert(0, str(ROOT / "vpp-server" / "app"))
import crypto_service  # noqa: E402

passed = 0


def ok(msg):
    global passed
    passed += 1
    print(f"  [PASS] {msg}")


def die(msg):
    print(f"  [FAIL] {msg}")
    sys.exit(1)


def b64url(obj) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def chains_to_ca(cert, ca) -> bool:
    try:
        ca.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False


def main():
    ca = x509.load_pem_x509_certificate((CERTS / "CA.crt").read_bytes())
    crypto_service.initialize()

    token = crypto_service.sign_jws({"message": "hello world"})
    print(f"JWS produced by the VPP:\n  {token[:56]}...{token[-16:]}\n")

    # --- header ---
    header = jwt.get_unverified_header(token)
    ok(f"header alg = {header['alg']}") if header.get("alg") == "RS256" \
        else die(f"unexpected alg: {header.get('alg')}")
    ok("header carries x5c (the VPP certificate)") if "x5c" in header \
        else die("no x5c header")
    ok(f"header typ = {header.get('typ')}")

    # --- x5c chains to the RA ---
    cert = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
    if chains_to_ca(cert, ca):
        ok(f"x5c certificate chains to RA ({cert.subject.rfc4514_string()})")
    else:
        die("x5c certificate does not chain to RA")

    pub_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # --- valid verification (algorithms pinned to RS256) ---
    payload = jwt.decode(token, pub_pem, algorithms=["RS256"])
    if payload.get("message") == "hello world":
        ok(f"signature verifies, payload recovered: {payload}")
    else:
        die(f"payload mismatch: {payload}")

    # --- tampered token must be rejected ---
    h, p, s = token.split(".")
    s_bad = ("A" if s[0] != "A" else "B") + s[1:]
    try:
        jwt.decode(f"{h}.{p}.{s_bad}", pub_pem, algorithms=["RS256"])
        die("tampered token verified (broken)")
    except Exception:
        ok("tampered token rejected")

    # --- alg:none forgery must be rejected ---
    forged = b64url({"alg": "none", "typ": "JWT"}) + "." \
        + b64url({"message": "hello world"}) + "."
    try:
        jwt.decode(forged, pub_pem, algorithms=["RS256"])
        die("alg:none forgery accepted (broken)")
    except Exception:
        ok("alg:none forgery rejected")

    print(f"\nSIGNATURE FORMAT (JWS) COMPLETE: {passed} checks passed.")


if __name__ == "__main__":
    main()
