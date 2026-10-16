import os
import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from . import ra_service, registry

CRL_HTTP_PORT = int(os.environ.get("TFG_CRL_HTTP_PORT", "8083"))


class _CrlHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/ra/crl":
            self.send_error(404)
            return
        body = ra_service.crl_der()
        self.send_response(200)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve_crl_over_http() -> ThreadingHTTPServer | None:
    """The CRL is signed, so it needs no TLS, and fetching it must not depend on a TLS
    check that could itself need the CRL. This listener serves the CRL and nothing else."""
    try:
        server = ThreadingHTTPServer(("0.0.0.0", CRL_HTTP_PORT), _CrlHandler)
    except OSError as e:
        print(f"[ca] CRL over HTTP not started on :{CRL_HTTP_PORT}: {e}")
        return None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@asynccontextmanager
async def lifespan(app: FastAPI):
    ra_service.initialize()
    crl_http = _serve_crl_over_http()
    print(f"[ca] CA loaded; CRL also served over HTTP on :{CRL_HTTP_PORT}")
    yield
    if crl_http:
        crl_http.shutdown()


app = FastAPI(title="Certificate Authority (CA)", version="0.2.0", lifespan=lifespan)


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "service": "ca"}


@app.get("/ra/certificate")
def ra_certificate() -> dict:
    return {"certificate": ra_service.ca_certificate_pem()}


class CsrRequest(BaseModel):
    csr: str  # PEM-encoded PKCS#10 certificate signing request


@app.post("/ra/issue")
def ra_issue(req: CsrRequest) -> dict:
    try:
        ra_service.refuse_requested_role(req.csr)
        return ra_service.issue_from_csr(req.csr)
    except ra_service.InvalidCSR as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ra_service.AlreadyEnrolled as e:
        raise HTTPException(status_code=409, detail=str(e))


class RevocationRequest(BaseModel):
    request: str  # compact JWS signed by the operator, naming the serial


@app.post("/ra/revoke")
def ra_revoke(req: RevocationRequest) -> dict:
    try:
        order = ra_service.verify_revocation_request(req.request)
    except ra_service.InvalidRequest as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ra_service.NotOperator as e:
        raise HTTPException(status_code=403, detail=str(e))

    serial = order["serial"]
    if registry.revoke(serial, order["reason"], by=order["requested_by"]):
        return {"revoked": serial, "reason": order["reason"],
                "requested_by": order["requested_by"],
                "crl_number": registry.crl_number()}
    known = registry.lookup(serial)
    if known is None:
        raise HTTPException(status_code=404, detail="serial not issued by this CA")
    raise HTTPException(status_code=409,
                        detail=f"already revoked at {known['revoked_at']}")


@app.get("/ra/crl")
def ra_crl() -> Response:
    return Response(content=ra_service.crl_der(), media_type="application/pkix-crl")


class RenewalRequest(BaseModel):
    request: str  # compact JWS signed with the CURRENT key, carrying a CSR for the new one


@app.post("/ra/renew")
def ra_renew(req: RenewalRequest) -> dict:
    try:
        return ra_service.renew_from_request(req.request)
    except ra_service.InvalidRequest as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ra_service.InvalidCSR as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ra_service.AlreadyEnrolled as e:
        raise HTTPException(status_code=409, detail=str(e))
