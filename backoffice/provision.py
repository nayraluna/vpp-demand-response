"""Provision the DR operator identity.

    python provision.py request [--algo rsa|ec]     generates key + CSR
    python provision.py install <signed.crt>        installs the certificate signed by the CA

"""
import argparse
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
# The role is granted when the CA host signs this CSR. The online endpoint refuses to.
SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "dr-operator"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "role=operator"),
])

def write_key(path, key) -> None:
    """Created 0600 from the start where the platform honours it (the Pi does, Windows does not)."""
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(pem)


def request(algo: str) -> None:
    key = (ec.generate_private_key(ec.SECP256R1()) if algo == "ec"
           else rsa.generate_private_key(public_exponent=65537, key_size=2048))
    csr = x509.CertificateSigningRequestBuilder().subject_name(SUBJECT).sign(key, hashes.SHA256())
    write_key(HERE / "operator.key", key)
    (HERE / "operator.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    print(f"operator: key generated, CSR for {SUBJECT.rfc4514_string()} at {HERE / 'operator.csr'}")


def install(cert: Path) -> None:
    issued = x509.load_pem_x509_certificate(cert.read_bytes())
    if issued.subject != SUBJECT:
        raise SystemExit(f"certificate is for {issued.subject.rfc4514_string()}, not for this operator")
    if cert.resolve() != (HERE / "operator.crt").resolve():
        shutil.copyfile(cert, HERE / "operator.crt")
    print(f"operator: certificate installed, serial {format(issued.serial_number, 'x')[:12]}...")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--algo", choices=("rsa", "ec"), default="ec")
    i = sub.add_parser("install")
    i.add_argument("cert", type=Path)
    args = ap.parse_args()
    request(args.algo) if args.cmd == "request" else install(args.cert)


if __name__ == "__main__":
    main()