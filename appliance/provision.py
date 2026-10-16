"""Factory step of an appliance: the key is generated in the HSM, only the CSR leaves it.

    python provision.py request [--ven ven-0001] [--power 2000] [--algo rsa|ec]
    python provision.py install <signed.crt> <root.crt> <platform-ca.crt>

The device leaves the factory with its certificate, the root as its only trust anchor,
and the platform issuing certificate it will meet in every owner's credential.
"""
import argparse
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import identity  # noqa: E402

HSM = ROOT_DIR / "certs"


def subject_for(ven: str, power: int) -> x509.Name:
    # OU=P=<watts> is the certified nominal power, what stops an appliance over-declaring it.
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ven),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"P={power}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Appliances"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    ])


def install(cert: Path, root: Path, platform_ca: Path) -> None:
    anchor = x509.load_pem_x509_certificate(root.read_bytes())
    issued = identity.install(cert, HSM / "VEN.crt")
    issuing = x509.load_pem_x509_certificate(platform_ca.read_bytes())
    if issued.issuer == anchor.subject or issuing.issuer != anchor.subject:
        raise SystemExit("the certificate and the platform issuing CA must both sit under the root being installed")
    for src, dest in ((root, HSM / "CA.crt"), (platform_ca, HSM / "platform-ca.crt")):
        if src.resolve() != dest.resolve():
            shutil.copyfile(src, dest)
    print(f"appliance: certificate {issued.subject.rfc4514_string()}, factory root "
          f"{anchor.subject.rfc4514_string()} and the platform issuing CA installed")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--ven", default="ven-0001")
    r.add_argument("--power", type=int, default=2000, help="nominal power in W")
    r.add_argument("--algo", choices=("rsa", "ec"), default="ec")
    i = sub.add_parser("install")
    i.add_argument("cert", type=Path)
    i.add_argument("root", type=Path)
    i.add_argument("platform_ca", type=Path)
    args = ap.parse_args()
    HSM.mkdir(exist_ok=True)
    if args.cmd == "request":
        subject = subject_for(args.ven, args.power)
        csr = identity.request(HSM, "VEN", subject, args.algo)
        print(f"appliance: key generated in the HSM, CSR for {subject.rfc4514_string()} at {csr}")
    else:
        install(args.cert, args.root, args.platform_ca)


if __name__ == "__main__":
    main()
