"""Provision the DR operator identity.

    python provision.py request [--algo rsa|ec]     generates key + CSR
    python provision.py install <signed.crt>        installs the certificate signed by the CA
"""
import argparse
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))
from pki import identity  # noqa: E402

HERE = Path(__file__).resolve().parent
# The role is granted when the CA host signs this CSR. The online endpoint refuses to.
SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "dr-operator"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "role=operator"),
])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("--algo", choices=("rsa", "ec"), default="ec")
    i = sub.add_parser("install")
    i.add_argument("cert", type=Path)
    args = ap.parse_args()
    if args.cmd == "request":
        csr = identity.request(HERE, "operator", SUBJECT, args.algo)
        print(f"operator: key generated, CSR for {SUBJECT.rfc4514_string()} at {csr}")
    else:
        issued = identity.install(args.cert, HERE / "operator.crt", expected_subject=SUBJECT)
        print(f"operator: certificate installed, serial {format(issued.serial_number, 'x')[:12]}...")


if __name__ == "__main__":
    main()
