"""Factory step of an appliance: the key is generated in the HSM, only the CSR leaves it.

    python provision.py request [--ven ven-0001] [--power 2000] [--algo rsa|ec]
    python provision.py install <signed.crt> <root.crt>
"""
import argparse
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

HSM = Path(__file__).resolve().parent.parent / "certs"


def subject_for(ven: str, power: int) -> x509.Name:
    # OU=P=<watts> is the certified nominal power, what stops an appliance over-declaring it.
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ven),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"P={power}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Appliances"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    ])


def request(ven: str, power: int, algo: str) -> None:
    key = (ec.generate_private_key(ec.SECP256R1()) if algo == "ec"
           else rsa.generate_private_key(public_exponent=65537, key_size=2048))
    subject = subject_for(ven, power)
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    (HSM / "VEN.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (HSM / "VEN.csr").write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    print(f"appliance: key generated in the HSM, CSR for {subject.rfc4514_string()} at {HSM / 'VEN.csr'}")


def install(cert: Path, root: Path) -> None:
    issued = x509.load_pem_x509_certificate(cert.read_bytes())
    anchor = x509.load_pem_x509_certificate(root.read_bytes())
    if issued.issuer != anchor.subject:
        raise SystemExit("certificate was not issued by the root being installed")
    if cert.resolve() != (HSM / "VEN.crt").resolve():
        shutil.copyfile(cert, HSM / "VEN.crt")
    if root.resolve() != (HSM / "CA.crt").resolve():
        shutil.copyfile(root, HSM / "CA.crt")
    print(f"appliance: certificate {issued.subject.rfc4514_string()} and factory root "
          f"{anchor.subject.rfc4514_string()} installed")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--ven", default="ven-0001")
    r.add_argument("--power", type=int, default=2000, help="nominal power in W")
    r.add_argument("--algo", choices=("rsa", "ec"), default="rsa")
    i = sub.add_parser("install")
    i.add_argument("cert", type=Path)
    i.add_argument("root", type=Path)
    args = ap.parse_args()
    HSM.mkdir(exist_ok=True)
    if args.cmd == "request":
        request(args.ven, args.power, args.algo)
    else:
        install(args.cert, args.root)


if __name__ == "__main__":
    main()
