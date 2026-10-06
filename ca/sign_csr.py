"""Sign a CSR offline, on the CA host, with a named profile.

This is how platform identities (the VPP, an appliance at the factory) obtain
their certificates: the component generates its own key pair, writes a CSR, and
only the CSR travels here. The network endpoint /ra/issue is for users and
operators and always applies the client profile. Everything signed here is
recorded in the register like any other certificate, so it can be revoked.

    python sign_csr.py --csr ../certs/vpp.csr --out ../certs/vpp.crt \\
        --profile tls-server+signing --san localhost,127.0.0.1,10.0.2.2
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from app import ra_service  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--csr", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--profile", choices=sorted(ra_service.PROFILES), default="client")
    ap.add_argument("--san", default="", help="comma separated, TLS server profiles only")
    ap.add_argument("--days", type=int, default=365)
    args = ap.parse_args()

    ra_service.initialize()
    san = [s.strip() for s in args.san.split(",") if s.strip()] or None
    issued = ra_service.issue_from_csr(args.csr.read_text(encoding="utf-8"),
                                       days=args.days, profile=args.profile, san=san)
    args.out.write_text(issued["certificate"])
    print(f"signed {issued['subject']} as {args.profile}, serial {issued['serial'][:12]}..., "
          f"until {issued['not_after'][:10]} -> {args.out}")


if __name__ == "__main__":
    main()
