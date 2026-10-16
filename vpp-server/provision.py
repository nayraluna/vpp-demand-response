"""Provision the VPP identity: the private key never leaves this component, only the CSR goes to the CA.

    python provision.py request [--algo rsa|ec]     writes vpp.key and vpp.csr
    python provision.py install <signed.crt>        writes vpp.crt (leaf and its issuing CA)
"""
import argparse
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import identity  # noqa: E402

CERTS = ROOT_DIR / "certs"
SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "VPP-VTN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--algo", choices=("rsa", "ec"), default="ec")
    i = sub.add_parser("install")
    i.add_argument("cert", type=Path)
    args = ap.parse_args()
    CERTS.mkdir(exist_ok=True)
    if args.cmd == "request":
        csr = identity.request(CERTS, "vpp", SUBJECT, args.algo)
        print(f"vpp: key generated, CSR for {SUBJECT.rfc4514_string()} at {csr}")
    else:
        issued = identity.install(args.cert, CERTS / "vpp.crt", expected_subject=SUBJECT)
        print(f"vpp: certificate installed, serial {format(issued.serial_number, 'x')[:12]}...")


if __name__ == "__main__":
    main()
