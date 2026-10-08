"""Create the platform root and the CA's own TLS certificate.

    python make_root.py [--algo rsa|ec] [--san 192.168.1.50,...]
"""
import argparse
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
CERTS = HERE.parent / "certs"
sys.path.insert(0, str(HERE))
from app import ra_service, registry  # noqa: E402

ROOT_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "VPP Platform Root CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
])
TLS_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "ca.vpp.local"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
])
# 10.0.2.2 is the Android emulator's alias for its host.
BASE_SAN = ["localhost", "127.0.0.1", "10.0.2.2"]


def generate_key(algo: str):
    if algo == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--algo", choices=("rsa", "ec"), default="ec")
    ap.add_argument("--san", default="", help="extra addresses for the CA's TLS certificate")
    ap.add_argument("--days", type=int, default=730)
    args = ap.parse_args()
    CERTS.mkdir(exist_ok=True)

    # Explicit basicConstraints and keyUsage: strict RFC 5280 validation rejects a root without them.
    root_key = generate_key(args.algo)
    now = datetime.datetime.now(datetime.timezone.utc)
    root = (
        x509.CertificateBuilder()
        .subject_name(ROOT_SUBJECT).issuer_name(ROOT_SUBJECT)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                       critical=False)
        .sign(root_key, hashes.SHA256())
    )
    write_key(CERTS / "CA.key", root_key)
    (CERTS / "CA.crt").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    print(f"root: {root.subject.rfc4514_string()}, valid {args.days} days")

    if registry.DB_FILE.exists():
        registry.DB_FILE.unlink()
        print("register wiped: certificates of the previous root no longer chain")
    ra_service.initialize()

    tls_key = generate_key(args.algo)
    csr = x509.CertificateSigningRequestBuilder().subject_name(TLS_SUBJECT).sign(
        tls_key, hashes.SHA256())
    san = BASE_SAN + [s.strip() for s in args.san.split(",") if s.strip()]
    issued = ra_service.issue_from_csr(csr.public_bytes(serialization.Encoding.PEM).decode(),
                                       profile="tls-server", san=san)
    write_key(CERTS / "server.key", tls_key)
    (CERTS / "server.crt").write_text(issued["certificate"])
    print(f"CA TLS: {issued['subject']}, serial {issued['serial'][:12]}..., SAN {', '.join(san)}")


if __name__ == "__main__":
    main()
