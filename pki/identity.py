"""What every component does to obtain its identity: a key that never leaves it, a CSR, an install."""
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def generate_key(algo: str = "ec", rsa_bits: int = 2048):
    if algo == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)


def write_key(path: Path, key) -> None:
    """PKCS#8 PEM, created 0600 from the start where the platform honours it (the Pi does, Windows does not)."""
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(pem)


def load_key(path: Path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def build_csr(key, subject: x509.Name) -> x509.CertificateSigningRequest:
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())


def write_csr(path: Path, csr: x509.CertificateSigningRequest) -> None:
    Path(path).write_bytes(csr.public_bytes(serialization.Encoding.PEM))


def request(directory: Path, name: str, subject: x509.Name, algo: str = "ec") -> Path:
    """Generate `<name>.key` and `<name>.csr` in `directory`; return the CSR path."""
    key = generate_key(algo)
    write_key(directory / f"{name}.key", key)
    write_csr(directory / f"{name}.csr", build_csr(key, subject))
    return directory / f"{name}.csr"


def install(cert_file: Path, dest: Path, expected_subject: x509.Name | None = None,
            expected_issuer: x509.Certificate | None = None) -> x509.Certificate:
    """Copy a signed certificate (with its chain) into place after checking it is the one expected."""
    issued = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
    if expected_subject is not None and issued.subject != expected_subject:
        raise SystemExit(f"certificate is for {issued.subject.rfc4514_string()}, "
                         f"not for {expected_subject.rfc4514_string()}")
    if expected_issuer is not None and issued.issuer != expected_issuer.subject:
        raise SystemExit("certificate was not issued under the root being installed")
    if Path(cert_file).resolve() != Path(dest).resolve():
        shutil.copyfile(cert_file, dest)
    return issued
