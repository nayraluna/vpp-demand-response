"""Offline acts of the root: create it, certify the two issuing CAs, publish the root CRL, and
give the RA its own TLS certificate under the platform issuing CA.

    python make_root.py [--algo rsa|ec] [--san 192.168.1.50,...]
"""
import argparse
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
ROOT_DIR = HERE.parent
CERTS = ROOT_DIR / "certs"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT_DIR))
from app import ca_service, ra_service, registry  # noqa: E402
from pki import identity  # noqa: E402

ROOT_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "VPP Platform Root CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
])
ISSUING_SUBJECTS = {
    "platform": x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "VPP Platform Issuing CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    ]),
    "device": x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Appliance Manufacturer Issuing CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Appliances"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
    ]),
}
TLS_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "ra.vpp.local"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VPP Platform"),
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
])
# 10.0.2.2 is the Android emulator's alias for its host.
BASE_SAN = ["localhost", "127.0.0.1", "10.0.2.2"]
ROOT_DB = HERE / "root.db"


def _ca_certificate(subject, public_key, issuer_cert, issuer_key, path_length, days, now):
    """A CA certificate: certificate and CRL signing only, and the path length the hierarchy allows."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
    )
    if issuer_cert is not None:
        builder = (builder
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()),
                                  critical=False)
                   .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                       full_name=[x509.UniformResourceIdentifier(f"{ca_service.CRL_BASE}/root")],
                       relative_name=None, reasons=None, crl_issuer=None)]), critical=False))
    return builder.sign(issuer_key, hashes.SHA256())


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--algo", choices=("rsa", "ec"), default="ec")
    ap.add_argument("--san", default="", help="extra addresses for the RA's TLS certificate")
    ap.add_argument("--days", type=int, default=730)
    args = ap.parse_args()
    CERTS.mkdir(exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)

    # Explicit basicConstraints and keyUsage: strict RFC 5280 validation rejects a root without them.
    # pathLen 1: the root certifies issuing CAs, and those certify end entities only.
    root_key = identity.generate_key(args.algo, rsa_bits=4096)
    root = _ca_certificate(ROOT_SUBJECT, root_key.public_key(), None, root_key, 1, args.days, now)
    identity.write_key(CERTS / "CA.key", root_key)
    (CERTS / "CA.crt").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    print(f"root: {root.subject.rfc4514_string()}, valid {args.days} days, pathLen 1")

    # A new root means every earlier certificate stops chaining: start the registers afresh.
    for db in (ROOT_DB, *(i.register.db_file for i in ca_service.ISSUERS.values())):
        if db.exists():
            db.unlink()
    root_register = registry.Register(ROOT_DB)
    root_register.initialize()

    for name, subject in ISSUING_SUBJECTS.items():
        issuer = ca_service.ISSUERS[name]
        key = identity.generate_key(args.algo)
        cert = _ca_certificate(subject, key.public_key(), root, root_key, 0, args.days, now)
        identity.write_key(issuer.key_file, key)
        issuer.cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        root_register.record(format(cert.serial_number, "x"), "", subject.rfc4514_string(), now,
                             now + datetime.timedelta(days=args.days),
                             cert.public_bytes(serialization.Encoding.PEM).decode(), "issuing-ca")
        print(f"issuing CA ({name}): {subject.rfc4514_string()}, pathLen 0")
    ca_service.sign_root_crl(root, root_key, root_register)
    print(f"root CRL: published to {ca_service.ROOT_CRL_FILE.name}, valid {ca_service.ROOT_CRL_VALIDITY.days} days")

    # The RA's own TLS identity: a platform leaf like any other service.
    ca_service.initialize()
    ra_service.initialize()
    tls_key = identity.generate_key(args.algo)
    csr_pem = identity.build_csr(tls_key, TLS_SUBJECT).public_bytes(serialization.Encoding.PEM).decode()
    san = ["ra.vpp.local", "ca.vpp.local"] + BASE_SAN + [s.strip() for s in args.san.split(",") if s.strip()]
    csr = ra_service.validate_csr(csr_pem, "tls-server", san)
    issued = ca_service.ISSUERS["platform"].sign_leaf(csr, "tls-server", san, 365, None)
    identity.write_key(CERTS / "server.key", tls_key)
    (CERTS / "server.crt").write_text(issued["certificate"])
    print(f"RA TLS: {issued['subject']}, serial {issued['serial'][:12]}..., SAN {', '.join(san)}")


if __name__ == "__main__":
    main()
