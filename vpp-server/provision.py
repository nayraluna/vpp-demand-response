"""Provision the VPP's own identity. The private key is generated here and
never leaves this component: only the CSR goes to the CA, and only the signed
certificate comes back.

    python provision.py request [--algo rsa|ec]     writes vpp.key and vpp.csr
    python provision.py install <signed.crt>        writes vpp.crt

In the development layout everything lives in ../certs/, which is where the
VPP services read their identity from.
"""
import argparse
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

CERTS = Path(__file__).resolve().parent.parent / "certs"
SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "VPP-VTN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
])


def request(algo: str) -> None:
    key = (ec.generate_private_key(ec.SECP256R1()) if algo == "ec"
           else rsa.generate_private_key(public_exponent=65537, key_size=2048))
    csr = x509.CertificateSigningRequestBuilder().subject_name(SUBJECT).sign(key, hashes.SHA256())
    (CERTS / "vpp.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (CERTS / "vpp.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    print(f"vpp: key generated, CSR for {SUBJECT.rfc4514_string()} at {CERTS / 'vpp.csr'}")


def install(cert: Path) -> None:
    issued = x509.load_pem_x509_certificate(cert.read_bytes())
    if issued.subject != SUBJECT:
        raise SystemExit(f"certificate is for {issued.subject.rfc4514_string()}, not for this VPP")
    if cert.resolve() != (CERTS / "vpp.crt").resolve():
        shutil.copyfile(cert, CERTS / "vpp.crt")
    print(f"vpp: certificate installed, serial {format(issued.serial_number, 'x')[:12]}...")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--algo", choices=("rsa", "ec"), default="rsa")
    i = sub.add_parser("install")
    i.add_argument("cert", type=Path)
    args = ap.parse_args()
    CERTS.mkdir(exist_ok=True)
    request(args.algo) if args.cmd == "request" else install(args.cert)


if __name__ == "__main__":
    main()
