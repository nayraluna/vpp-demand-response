import argparse
import json
import sys
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "vpp-server"))
from app import availability as av  # noqa: E402

CA_FILE = str(ROOT / "certs" / "CA.crt")
CA, MTLS = "https://127.0.0.1:8081", "https://127.0.0.1:8443"
KEY_FILE = Path(__file__).resolve().parent / "operator.key"
CRT_FILE = Path(__file__).resolve().parent / "operator.crt"


def init_credential(force: bool = False) -> tuple[str, str]:
    """Issue (or reuse) the operator credential: an RA certificate whose subject
    carries OU=role=operator. The private key never leaves this machine."""
    if KEY_FILE.exists() and CRT_FILE.exists() and not force:
        return str(CRT_FILE), str(KEY_FILE)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, "dr-operator"),
               x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "role=operator"),
           ]))
           .sign(key, hashes.SHA256()))
    r = requests.post(f"{CA}/ra/issue",
                      json={"csr": csr.public_bytes(serialization.Encoding.PEM).decode()},
                      verify=CA_FILE)
    r.raise_for_status()
    CRT_FILE.write_text(r.json()["certificate"])
    KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return str(CRT_FILE), str(KEY_FILE)


def _hour_to_slot(text: str) -> int:
    """"18" or "18:30" -> slot index (30-minute slots)."""
    hour, _, minute = text.partition(":")
    return av.slot_index(int(hour), int(minute or 0))


def _request(path: str, body: dict) -> dict:
    client = init_credential()
    r = requests.post(f"{MTLS}{path}", json=body, cert=client, verify=CA_FILE)
    payload = r.json()
    if r.status_code not in (200, 409):  # 409 = infeasible activation, reported
        raise SystemExit(f"{path} -> HTTP {r.status_code}: {json.dumps(payload)}")
    return payload


def _report(body: dict, requested: int | None = None) -> None:
    if body.get("feasible") is False:
        print(f"NOT POSSIBLE: {body.get('reason', 'infeasible')}")
    else:
        chosen = body.get("selected") or body.get("activations") or []
        print(f"{'ACTIVATED' if body.get('status') == 'activated' else 'FEASIBLE'}: "
              f"{len(chosen)} appliance(s), {body.get('aggregated_power')} W "
              f"aggregated for {body.get('requested_power', requested)} W requested "
              f"in {body.get('interval')} ({body.get('day')})")
        for s in chosen:
            extra = f"  [{s['activation_id']}]" if "activation_id" in s else ""
            print(f"  {s['ven']}  {s.get('power', '')} W{extra}")
    for rej in body.get("rejected", []):
        print(f"  rejected: {rej['ven']} - {rej['reason']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Backoffice - DR operator trigger.")
    sub = parser.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init", help="obtain the operator credential from the RA")
    i.add_argument("--force", action="store_true",
                   help="reissue even if a credential already exists")

    for name, help_text in (("select", "dry-run: who would serve the reduction"),
                            ("activate", "issue the reduction (writes activations)")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--power", type=int, required=True, help="reduction in W")
        p.add_argument("--day", required=True, choices=av.DAYS)
        p.add_argument("--from", dest="start", required=True, metavar="HH[:MM]")
        p.add_argument("--to", dest="end", required=True, metavar="HH[:MM]")
        if name == "activate":
            p.add_argument("--action", default="reduce",
                           choices=("reduce", "shutdown"))

    args = parser.parse_args()
    if args.command == "init":
        crt, _ = init_credential(force=args.force)
        subject = x509.load_pem_x509_certificate(
            Path(crt).read_bytes()).subject.rfc4514_string()
        print(f"operator credential ready: {subject} ({crt})")
        return

    body = {"power_w": args.power, "day": args.day,
            "slot_start": _hour_to_slot(args.start),
            "slot_end": _hour_to_slot(args.end)}
    if args.command == "activate":
        body["action"] = args.action
        _report(_request("/dr/activate", body), requested=args.power)
    else:
        _report(_request("/dr/select", body), requested=args.power)


if __name__ == "__main__":
    main()
