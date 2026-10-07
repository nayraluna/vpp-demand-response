"""Build the whole development PKI the way a deployment would, one component at
a time: each one generates its own key pair and a CSR, the CA signs the CSR
offline, and the component installs what it gets back. Private keys never
travel, CSRs and certificates do.

    python provision_all.py [--algo rsa|ec] [--san 192.168.1.50,...]

EXTRA_SAN_IPS is honoured too, so a phone or a Raspberry Pi can reach the TLS
endpoints by this machine's address. Everything lands in certs/ under the names
the services, the gates and the Android project already use.

Re-running this creates a new root, so the Android app's bundled copy of
CA.crt, the operator credential and anything deployed on a Pi have to be
refreshed afterwards (see the appendix of RUNBOOK.md).
"""
import argparse
import os
import subprocess
import functools
import sys
from pathlib import Path

print = functools.partial(print, flush=True)

ROOT = Path(__file__).resolve().parent
CERTS = ROOT / "certs"
PY = sys.executable
BASE_SAN = "localhost,127.0.0.1,10.0.2.2"


def run(*args: str) -> None:
    print(f"$ {' '.join(a if ' ' not in a else repr(a) for a in args)}")
    subprocess.run([PY, *args], cwd=str(ROOT), check=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--algo", choices=("rsa", "ec"), default="rsa",
                    help="key algorithm for every identity (RSA until the verifiers are algorithm agnostic)")
    ap.add_argument("--san", default=os.environ.get("EXTRA_SAN_IPS", ""),
                    help="extra TLS addresses, comma separated (defaults to EXTRA_SAN_IPS)")
    args = ap.parse_args()
    extra = [s.strip() for s in args.san.split(",") if s.strip()]
    san = ",".join([BASE_SAN, *extra])
    CERTS.mkdir(exist_ok=True)

    print("== 1. the CA creates its root and its own TLS certificate ==")
    run("ca/make_root.py", "--algo", args.algo, "--san", ",".join(extra))

    print("\n== 2. the VPP generates its key and asks for a certificate ==")
    run("vpp-server/provision.py", "request", "--algo", args.algo)
    run("ca/sign_csr.py", "--csr", "certs/vpp.csr", "--out", "certs/vpp.crt",
        "--profile", "tls-server+signing", "--san", san)
    run("vpp-server/provision.py", "install", "certs/vpp.crt")

    print("\n== 3. the appliance generates its key in the HSM and is certified at the factory ==")
    run("appliance/provision.py", "request", "--algo", args.algo)
    run("ca/sign_csr.py", "--csr", "certs/VEN.csr", "--out", "certs/VEN.crt",
        "--profile", "client")
    run("appliance/provision.py", "install", "certs/VEN.crt", "certs/CA.crt")

    for stale in ("vpp.p12", "VEN.p12", "CA.srl", "vpp.ext", "server.ext", "VEN.ext",
                  "server.csr"):
        (CERTS / stale).unlink(missing_ok=True)

    print("\n== done ==")
    for name in ("CA.crt", "server.crt", "vpp.crt", "VEN.crt"):
        subprocess.run([PY, "-c",
                        "import sys; from cryptography import x509; "
                        "c = x509.load_pem_x509_certificate(open(sys.argv[1],'rb').read()); "
                        "print(f'  {sys.argv[1]:16} {c.subject.rfc4514_string()}')",
                        str(CERTS / name)], check=True)
    print("\nNext: copy certs/CA.crt over android-app/app/src/main/res/raw/ca.crt and rebuild"
          " the APK, reissue the operator credential, and re-provision the Pi from its own CSR"
          " (RUNBOOK.md, appendix).")


if __name__ == "__main__":
    main()
