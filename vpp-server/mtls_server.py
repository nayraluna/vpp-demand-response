import datetime
import json
import os
import secrets
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app import (availability, crypto_service, db,  # noqa: E402
                 evidence, owner_proof, remuneration, revocation, scheduling)

CERTS = Path(__file__).resolve().parent.parent / "certs"
# run_all.ps1 pins 127.0.0.1 so a LAN appliance with the same VEN identity cannot consume gate activations.
HOST = os.environ.get("TFG_MTLS_HOST", "0.0.0.0")
PORT = 8443


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _refused_as_revoked(self, cert) -> bool:
        # TLS only checks the chain; revocation is checked here before any handler sees the identity.
        try:
            if revocation.is_revoked(cert):
                self._json(403, {"error": "certificate revoked",
                                 "subject": cert.subject.rfc4514_string()})
                return True
        except revocation.Unavailable as e:
            self._json(503, {"error": str(e)})
            return True
        return False

    def do_GET(self):
        der = self.connection.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        if self._refused_as_revoked(cert):
            return
        subject = cert.subject.rfc4514_string()

        # The appliance polls with its VEN certificate, so it is routed before the user lookup.
        if self.path == "/openadr/poll":
            return self._openadr_poll(subject)

        user = db.get_user(subject)
        if user is None:
            return self._json(403, {"error": "valid platform certificate but not enrolled",
                                    "subject": subject})

        if self.path == "/session":
            return self._json(200, {"authenticated": True, "user": subject,
                                    "enrolled_at": user["enrolled_at"]})
        if self.path == "/availability":
            out = []
            for appliance in db.list_appliances_by_owner(subject):
                declared = db.get_availability(appliance["ven_subject"])
                out.append({**appliance,
                            "availability": declared["slots"] if declared else None,
                            "version": declared.get("version") if declared else None,
                            "updated_at": declared["updated_at"] if declared else None})
            return self._json(200, {"user": subject, "appliances": out})
        if self.path == "/participation":
            # Only participations with verified evidence: no reward without proof.
            records = db.evidence_for_owner(subject)
            return self._json(200, {"user": subject,
                                    **remuneration.summarise(records)})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        der = self.connection.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        if self._refused_as_revoked(cert):
            return
        subject = cert.subject.rfc4514_string()

        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid JSON"})

        if self.path == "/appliances/owner-proof":
            return self._owner_proof(subject, body)
        if self.path == "/availability":
            return self._availability(subject, body)
        if self.path == "/dr/select":
            return self._dr_select(cert, subject, body)
        if self.path == "/dr/activate":
            return self._dr_activate(cert, subject, body)
        if self.path == "/evidence":
            return self._evidence(subject, body)
        if self.path == "/openadr/register":
            return self._openadr_register(cert, subject, body)
        return self._json(404, {"error": "not found"})

    def _availability(self, user_subject: str, body: dict):
        """The user declares when an appliance may be curtailed, as an owner-signed versioned JWS."""
        if db.get_user(user_subject) is None:
            return self._json(403, {"error": "valid platform certificate but not enrolled"})

        ven = body.get("ven", "")
        appliance = db.get_appliance(ven)
        if appliance is None:
            return self._json(404, {"error": f"unknown appliance {ven!r}"})
        if appliance["owner"] != user_subject:
            return self._json(403, {"error": "appliance belongs to another user"})

        try:
            calendar = availability.verify_signed(body.get("jws", ""), user_subject)
        except availability.InvalidAvailability as e:
            return self._json(400, {"error": str(e)})

        # Same monotonicity the appliance enforces, so a stale declaration never overwrites a newer one.
        current = db.get_availability(ven)
        if current and current.get("version") \
                and calendar["version"] <= current["version"]:
            return self._json(400, {
                "error": f"stale calendar version {calendar['version']} "
                         f"(current is {current['version']})"})

        db.set_availability(ven, calendar["slots"],
                            datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            jws=body.get("jws"), version=calendar["version"])
        declared = sum(day.count("1") for day in calendar["slots"].values())
        return self._json(200, {
            "status": "declared", "ven": ven,
            "version": calendar["version"],
            "slot_minutes": availability.SLOT_MINUTES,
            "slots_per_day": availability.SLOTS_PER_DAY,
            "declared_slots": declared,
        })

    def _owner_proof(self, user_subject: str, body: dict):
        """Bind an appliance to the user authenticated on this channel."""
        if db.get_user(user_subject) is None:
            return self._json(403, {"error": "valid platform certificate but not enrolled",
                                    "subject": user_subject})
        try:
            bound = owner_proof.verify(body.get("owner_proof", ""), user_subject)
        except owner_proof.OwnershipMismatch as e:
            return self._json(403, {"error": str(e)})
        except owner_proof.InvalidOwnerProof as e:
            return self._json(400, {"error": str(e)})

        # Parameters come from the verified payload; the proof signature itself is not stored.
        db.add_appliance(
            bound["ven_subject"], bound["owner"], bound["cert_pem"],
            bound["nominal_power"], bound["max_curtail"], bound["recovery"],
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        return self._json(200, {
            "status": "bound",
            "ven": bound["ven_subject"],
            "owner": bound["owner"],
            "parameters": {"P": bound["nominal_power"],
                           "max": bound["max_curtail"],
                           "rec": bound["recovery"]},
        })

    def _dr_select(self, cert, subject: str, body: dict):
        """The DR operator requests a reduction; returns the selection or why it cannot be served."""
        if not self._is_operator(cert):
            return self._json(403, {"error": "only the DR operator may request a "
                                             "reduction", "subject": subject})
        try:
            result = scheduling.select(
                power_w=int(body["power_w"]), day=body["day"],
                slot_start=int(body["slot_start"]), slot_end=int(body["slot_end"]),
                appliances=db.list_appliances_for_selection(),
            )
        except (KeyError, TypeError, ValueError) as e:
            return self._json(400, {"error": f"invalid reduction request: {e}"})
        return self._json(200, result)

    @staticmethod
    def _is_operator(cert) -> bool:
        """Role attribute OU=role=operator. Prototype limitation: the RA does not validate it at issuance."""
        roles = [a.value for a in cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME)]
        return "role=operator" in roles

    def _openadr_poll(self, ven_subject: str):
        """OpenADR pull: the appliance retrieves its pending activations, calendar and CRL."""
        if db.get_registration(ven_subject) is None:
            return self._json(403, {"error": "appliance is not a registered VEN",
                                    "subject": ven_subject})
        pending = db.pending_activations(ven_subject)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for activation in pending:
            db.mark_delivered(activation["activation_id"], now)
        # Calendar and CRL ride along verbatim: the appliance verifies both itself.
        declared = db.get_availability(ven_subject)
        return self._json(200, {"ven": ven_subject, "activations": pending,
                                "calendar": declared.get("jws") if declared else None,
                                "crl": db.get_crl()})

    def _dr_activate(self, cert, subject: str, body: dict):
        """Issue activations to the selected appliances; the random id is what the evidence must name."""
        if not self._is_operator(cert):
            return self._json(403, {"error": "only the DR operator may activate"})
        action = body.get("action", "reduce")
        if action not in ("reduce", "shutdown"):
            return self._json(400, {"error": "action must be 'reduce' or 'shutdown'"})
        try:
            selection = scheduling.select(
                power_w=int(body["power_w"]), day=body["day"],
                slot_start=int(body["slot_start"]), slot_end=int(body["slot_end"]),
                appliances=db.list_appliances_for_selection(),
            )
        except (KeyError, TypeError, ValueError) as e:
            return self._json(400, {"error": f"invalid activation request: {e}"})

        if not selection["feasible"]:
            return self._json(409, {"status": "not-activated", **selection})

        now = datetime.datetime.now(datetime.timezone.utc)
        ends_at = now + datetime.timedelta(minutes=selection["duration_minutes"])
        issued = []
        for chosen in selection["selected"]:
            activation = {
                "activation_id": "act-" + secrets.token_hex(16),
                "ven_subject": chosen["ven"],
                "day": selection["day"],
                "slot_start": selection["slot_start"],
                "slot_end": selection["slot_end"],
                "action": action,
                "issued_at": now.isoformat(),
                "ends_at": ends_at.isoformat(),
            }
            db.add_activation(activation)
            issued.append({"ven": chosen["ven"], "power": chosen["power"],
                           "activation_id": activation["activation_id"]})
        return self._json(200, {
            "status": "activated", "action": action,
            "interval": selection["interval"], "day": selection["day"],
            "aggregated_power": selection["aggregated_power"],
            "activations": issued,
        })

    def _evidence(self, ven_subject: str, body: dict):
        """The appliance submits signed participation evidence."""
        try:
            verified = evidence.verify(body.get("evidence", ""), ven_subject)
        except evidence.DuplicateEvidence as e:
            return self._json(409, {"error": str(e)})
        except evidence.InvalidEvidence as e:
            return self._json(400, {"error": str(e)})

        # The signed JWS is kept verbatim: it is the auditable record.
        db.add_evidence(
            verified["activation_id"], verified["ven_subject"],
            verified["executed_at"], verified["reduction_pct"],
            body["evidence"],
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        return self._json(200, {"status": "verified", **verified})

    def _openadr_register(self, cert, subject: str, body: dict):
        """OpenADR EiRegisterParty: the VEN registers with the VTN."""
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ven_cn = cn[0].value if cn else subject

        existing = db.get_registration(subject)
        if existing:
            ven_id, reg_id = existing["ven_id"], existing["registration_id"]
        else:
            ven_id = ven_cn
            reg_id = "reg-" + secrets.token_hex(8)
            db.add_registration(
                subject, ven_id, reg_id,
                body.get("venName", ven_cn),
                json.dumps(body.get("applianceProfile", {})),
                datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )
        self._json(200, {
            "oadrResponse": {"responseCode": 200, "responseDescription": "OK"},
            "oadrProfileName": body.get("oadrProfileName", "2.0b"),
            "venID": ven_id,
            "registrationID": reg_id,
            "oadrRequestedOadrPollFreq": "PT60S",
        })

    def log_message(self, *args):
        pass  # keep the console quiet


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # clients without a valid certificate fail the handshake


def main():
    db.initialize()
    crypto_service.initialize()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / "vpp.crt"), str(CERTS / "vpp.key"))
    ctx.load_verify_locations(str(CERTS / "CA.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    httpd = QuietServer((HOST, PORT), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[vpp-mtls] mutual-TLS session endpoint on https://{HOST}:{PORT} "
          f"(CERT_REQUIRED, trust anchor = RA/CA.crt)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
