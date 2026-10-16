"""Build the development PKI.

Usage: python provision_all.py [--algo rsa|ec] [--san 192.168.1.50,...]
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CERTS = ROOT / "certs"
PY = sys.executable
BASE_SAN = "localhost,127.0.0.1,10.0.2.2"


def run(*args: str) -> None:
    subprocess.run([PY, *args], cwd=str(ROOT), check=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument(
        "--algo",
        choices=("rsa", "ec"),
        default="ec",
        help="Key algorithm for all platform identities",
    )
    ap.add_argument(
        "--san",
        default=os.environ.get("EXTRA_SAN_IPS", ""),
        help="Additional TLS addresses, comma separated",
    )
    args = ap.parse_args()

    extra = [s.strip() for s in args.san.split(",") if s.strip()]
    san = ",".join([BASE_SAN, *extra])
    CERTS.mkdir(exist_ok=True)

    # Create the root CA and TLS certificate.
    run("ca/make_root.py", "--algo", args.algo, "--san", ",".join(extra))

    # Generate and sign the VPP server certificate.
    run("vpp-server/provision.py", "request", "--algo", args.algo)
    run(
        "ca/sign_csr.py",
        "--csr", "certs/vpp.csr",
        "--out", "certs/vpp.crt",
        "--profile", "tls-server+signing",
        "--san", san,
    )
    run("vpp-server/provision.py", "install", "certs/vpp.crt")

    # Generate and sign the appliance certificate.
    run("appliance/provision.py", "request", "--algo", args.algo)
    run(
        "ca/sign_csr.py",
        "--csr", "certs/VEN.csr",
        "--out", "certs/VEN.crt",
        "--profile", "client",
    )
    run(
        "appliance/provision.py",
        "install", "certs/VEN.crt", "certs/CA.crt",
    )

    # Generate and sign the backoffice operator certificate.
    run("backoffice/provision.py", "request", "--algo", args.algo)
    run(
        "ca/sign_csr.py",
        "--csr", "backoffice/operator.csr",
        "--out", "backoffice/operator.crt",
        "--profile", "client",
    )
    run("backoffice/provision.py", "install", "backoffice/operator.crt")

    # Remove obsolete certificate artifacts.
    for stale in (
        "vpp.p12",
        "VEN.p12",
        "CA.srl",
        "vpp.ext",
        "server.ext",
        "VEN.ext",
        "server.csr",
    ):
        (CERTS / stale).unlink(missing_ok=True)

    # Display the subjects of the generated certificates.
    for name in ("CA.crt", "server.crt", "vpp.crt", "VEN.crt"):
        subprocess.run(
            [
                PY,
                "-c",
                "import sys; from cryptography import x509; "
                "c = x509.load_pem_x509_certificate(open(sys.argv[1], 'rb').read()); "
                "print(f'{sys.argv[1]:16} {c.subject.rfc4514_string()}')",
                str(CERTS / name),
            ],
            check=True,
        )


if __name__ == "__main__":
    main()
