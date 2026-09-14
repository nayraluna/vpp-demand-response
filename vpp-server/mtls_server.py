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
                 evidence, owner_proof, remuneration, scheduling)

CERTS = Path(__file__).resolve().parent.parent / "certs"
# All interfaces by default: emulator (10.0.2.2) AND physical devices on the
# LAN. TFG_MTLS_HOST overrides it; run_all.ps1 pins 127.0.0.1 so the gates are
# isolated from any OTHER holder of the VEN identity on the LAN (the deployed
# Raspberry Pi polls this endpoint every minute and would otherwise consume
# the activations the gates issue for the local appliance).
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

    def do_GET(self):
        # The client cert was already validated against the RA by the TLS layer
        # (CERT_REQUIRED + CA.crt). Read it and identify the enrolled user.
        der = self.connection.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
        subject = cert.subject.rfc4514_string()

        # The appliance polls with its VEN certificate, not a user certificate:
        # this is the pull leg of the operational phase (outbound, NAT-safe).
        if self.path == "/openadr/poll":
            return self._openadr_poll(subject)

        user = db.get_user(subject)
        if user is None:
            return self._json(403, {"error": "valid RA certificate but not enrolled",
                                    "subject": subject})

        if self.path == "/session":
            return self._json(200, {"authenticated": True, "user": subject,
                                    "enrolled_at": user["enrolled_at"]})
        if self.path == "/availability":
            # Everything this user owns, with the calendar declared for each.
            out = []
            for appliance in db.list_appliances_by_owner(subject):
                declared = db.get_availability(appliance["ven_subject"])
                out.append({**appliance,
                            "availability": declared["slots"] if declared else None,
                            "version": declared.get("version") if declared else None,
                            "updated_at": declared["updated_at"] if declared else None})
            return self._json(200, {"user": subject, "appliances": out})
        if self.path == "/participation":
            # What the mobile application shows the user: the participations of
            # their appliances that the VPP has VERIFIED, with the energy not
            # consumed and what it earned them. Nothing that lacks verified
            # evidence appears here, so no reward can be claimed without proof.
            records = db.evidence_for_owner(subject)
            return self._json(200, {"user": subject,
                                    **remuneration.summarise(records)})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        # The client certificate was already validated against the RA by the TLS
        # layer; who it identifies depends on the endpoint (the user forwards the
        # owner proof, the appliance registers itself as a VEN).
        der = self.connection.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
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
        """Operational step 1: the user declares when an appliance may be curtailed.

        The calendar arrives as a JWS signed by the owner, carrying a
        monotonically increasing version. The VPP stores the parsed slots for
        participant selection and keeps the signed artefact verbatim: the
        appliance retrieves it through its outbound polling and re-verifies
        signature and version itself, so the VPP cannot modify what the owner
        signed nor roll it back.
        """
        if db.get_user(user_subject) is None:
            return self._json(403, {"error": "valid RA certificate but not enrolled"})

        ven = body.get("ven", "")
        appliance = db.get_appliance(ven)
        if appliance is None:
            return self._json(404, {"error": f"unknown appliance {ven!r}"})
        # Only the owner recorded by the owner proof may declare availability.
        if appliance["owner"] != user_subject:
            return self._json(403, {"error": "appliance belongs to another user"})

        try:
            calendar = availability.verify_signed(body.get("jws", ""), user_subject)
        except availability.InvalidAvailability as e:
            return self._json(400, {"error": str(e)})

        # Same monotonicity the appliance enforces, applied at the door: a
        # stale declaration (e.g. two user sessions racing) never overwrites a
        # newer one, so selection and the appliance stay convergent.
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
        """Registration: bind an appliance to the user authenticated here."""
        if db.get_user(user_subject) is None:
            return self._json(403, {"error": "valid RA certificate but not enrolled",
                                    "subject": user_subject})
        try:
            bound = owner_proof.verify(body.get("owner_proof", ""), user_subject)
        except owner_proof.OwnershipMismatch as e:
            return self._json(403, {"error": str(e)})
        except owner_proof.InvalidOwnerProof as e:
            return self._json(400, {"error": str(e)})

        # The ownership relation and the declared parameters are recorded; the
        # proof signature has served its purpose and is not stored.
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
        """Operational step 2: the DR operator requests a reduction; the VPP
        selects the participants, or reports that it cannot be served.

        The operator is recognised by the role attribute in its RA-issued
        certificate (OU=role=operator). PROTOTYPE LIMITATION: the RA currently
        honours whatever subject a CSR asks for, so this role is not enforced at
        issuance; a real deployment would have the RA validate role attributes.
        """
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
        """The DR operator is recognised by a role attribute in its RA certificate.

        PROTOTYPE LIMITATION: the RA honours whatever subject a CSR asks for, so
        the role is not enforced at issuance; a real deployment would have the RA
        validate role attributes before signing.
        """
        roles = [a.value for a in cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME)]
        return "role=operator" in roles

    def _openadr_poll(self, ven_subject: str):
        """The appliance retrieves its pending activations (OpenADR pull model).

        The channel already authenticated both ends, so the appliance knows the
        activation comes from the legitimate VPP; the activation identifier and
        the nonce are what protect it once it has left the channel.
        """
        if db.get_registration(ven_subject) is None:
            return self._json(403, {"error": "appliance is not a registered VEN",
                                    "subject": ven_subject})
        pending = db.pending_activations(ven_subject)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for activation in pending:
            db.mark_delivered(activation["activation_id"], now)
        # The current owner-signed calendar rides along verbatim: the appliance
        # verifies its signature and version itself (the VPP only relays it).
        declared = db.get_availability(ven_subject)
        return self._json(200, {"ven": ven_subject, "activations": pending,
                                "calendar": declared.get("jws") if declared else None})

    def _dr_activate(self, cert, subject: str, body: dict):
        """Operational step 3: issue activations to the selected appliances.

        Selection runs first; if the request cannot be served nothing is
        activated (409). Each activation carries an activation identifier and a
        128-bit nonce, which is what stops a captured activation from being
        replayed once it has left the channel.
        """
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
                "activation_id": "act-" + secrets.token_hex(8),
                "ven_subject": chosen["ven"],
                "day": selection["day"],
                "slot_start": selection["slot_start"],
                "slot_end": selection["slot_end"],
                "action": action,
                "nonce": secrets.token_hex(16),      # 128-bit, makes it unique
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
        """Operational step 4: the appliance submits signed participation evidence."""
        try:
            verified = evidence.verify(body.get("evidence", ""), ven_subject)
        except evidence.DuplicateEvidence as e:
            return self._json(409, {"error": str(e)})
        except evidence.InvalidEvidence as e:
            return self._json(400, {"error": str(e)})

        # The signature is kept verbatim: it IS the auditable record.
        db.add_evidence(
            verified["activation_id"], verified["ven_subject"],
            verified["executed_at"], verified["reduction_pct"],
            body["evidence"],
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        return self._json(200, {"status": "verified", **verified})

    def _openadr_register(self, cert, subject: str, body: dict):
        """OpenADR EiRegisterParty (step 8c): the VEN registers with the VTN."""
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ven_cn = cn[0].value if cn else subject

        # oadrCreatePartyRegistration -> oadrCreatedPartyRegistration
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
        pass  # ignore TLS handshake failures (clients without a valid cert)


def main():
    db.initialize()
    crypto_service.initialize()  # loads the VPP identity + the RA trust anchor
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / "vpp.crt"), str(CERTS / "vpp.key"))
    ctx.load_verify_locations(str(CERTS / "CA.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED  # mutual TLS: client MUST present a cert
    httpd = QuietServer((HOST, PORT), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[vpp-mtls] mutual-TLS session endpoint on https://{HOST}:{PORT} "
          f"(CERT_REQUIRED, trust anchor = RA/CA.crt)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
