"""Sign a CSR offline, on the CA host, with a named issuer and profile.

    python sign_csr.py --csr ../certs/vpp.csr --out ../certs/vpp.crt \\
        --issuer platform --profile tls-server+signing --san localhost,127.0.0.1,10.0.2.2
    python sign_csr.py --csr ../certs/VEN.csr --out ../certs/VEN.crt --issuer device

The device issuing CA signs only here: it is the factory line, never online.
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from app import ca_service, ra_service, registry  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--csr", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--issuer", choices=sorted(ca_service.ISSUERS), default="platform")
    ap.add_argument("--profile", choices=sorted(ca_service.PROFILES), default="client")
    ap.add_argument("--san", default="", help="comma separated, TLS server profiles only")
    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--supersedes", metavar="SERIAL", type=registry.normalize_serial,
                    help="renewal: the serial this certificate replaces, revoked as superseded")
    args = ap.parse_args()

    ca_service.initialize()
    ra_service.initialize()
    san = [s.strip() for s in args.san.split(",") if s.strip()] or None
    # The same request-level rules the RA applies online: the factory line is the RA of its domain.
    csr = ra_service.validate_csr(args.csr.read_text(encoding="utf-8"), args.profile, san)
    issued = ca_service.ISSUERS[args.issuer].sign_leaf(csr, args.profile, san, args.days, args.supersedes)
    args.out.write_text(issued["certificate"])
    print(f"signed {issued['subject']} by the {args.issuer} CA as {args.profile}, "
          f"serial {issued['serial'][:12]}..., until {issued['not_after'][:10]} -> {args.out}")


if __name__ == "__main__":
    main()
