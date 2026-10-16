"""How the RA reaches the CA process: a private loopback channel, never exposed outside the host."""
import os

import requests
from cryptography import x509

CA_URL = os.environ.get("TFG_CA_URL", "http://127.0.0.1:8084")


class Refused(Exception):
    """The CA refused the request; carries the HTTP status to relay."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def _post(path: str, body: dict) -> dict:
    r = requests.post(f"{CA_URL}{path}", json=body, timeout=10)
    if r.status_code != 200:
        raise Refused(r.status_code, r.json().get("detail", r.text))
    return r.json()


def sign(csr_pem: str, profile: str, san: list[str] | None, days: int, supersedes: str | None) -> dict:
    return _post("/sign", {"csr": csr_pem, "profile": profile, "san": san,
                           "days": days, "supersedes": supersedes})


def revoke(serial: str, reason: str, by: str) -> dict:
    return _post("/revoke", {"serial": serial, "reason": reason, "by": by})


def crl(issuer: str) -> bytes:
    r = requests.get(f"{CA_URL}/crl/{issuer}", timeout=10)
    r.raise_for_status()
    return r.content


def is_revoked(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    """Look the certificate up in its issuer's current list, and the issuer in the root's."""
    from . import ca_service  # noqa: PLC0415 (import here keeps this module free of the CA layout)
    name = next(n for n, i in ca_service.ISSUERS.items()
                if x509.load_pem_x509_certificate(i.cert_file.read_bytes()).subject == issuer_cert.subject)
    leaf_list = x509.load_der_x509_crl(crl(name))
    root_list = x509.load_der_x509_crl(crl("root"))
    return (leaf_list.get_revoked_certificate_by_serial_number(cert.serial_number) is not None
            or root_list.get_revoked_certificate_by_serial_number(issuer_cert.serial_number) is not None)
