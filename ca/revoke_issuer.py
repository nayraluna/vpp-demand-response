"""Offline act of the root: revoke an issuing CA and re-publish the root CRL.

    python revoke_issuer.py --issuer platform --reason cACompromise

Every certificate under that issuing CA stops validating as soon as the relying parties
fetch the new root CRL. Recovery is a new issuing CA signed by the root, which is why the
root key is kept offline and apart.
"""
import argparse
import sys
from pathlib import Path

from cryptography import x509

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
from app import ca_service, registry  # noqa: E402
from pki import identity  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--issuer", choices=sorted(ca_service.ISSUERS), required=True)
    ap.add_argument("--reason", default="cACompromise", choices=sorted(ca_service.REASONS))
    args = ap.parse_args()

    root = ca_service.root_certificate()
    root_key = identity.load_key(ca_service.ROOT_KEY_FILE)
    register = registry.Register(HERE / "root.db")
    register.initialize()
    issuing = x509.load_pem_x509_certificate(ca_service.ISSUERS[args.issuer].cert_file.read_bytes())
    serial = format(issuing.serial_number, "x")
    if not register.revoke(serial, args.reason, by=root.subject.rfc4514_string()):
        raise SystemExit(f"{args.issuer} issuing CA (serial {serial[:12]}...) is already revoked")
    ca_service.sign_root_crl(root, root_key, register)
    print(f"revoked the {args.issuer} issuing CA ({args.reason}), root CRL #{register.crl_number()} published")


if __name__ == "__main__":
    main()
