"""The RA process: the platform's issuance front, holding no key.

It validates requests over TLS on :8081, hands them to the CA process over loopback, and
distributes the trust anchor and the CRLs, also over plain HTTP on :8083 for the clients
that follow a distribution point.
"""
import os
import threading
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from . import ca_client, ra_service

CRL_HTTP_PORT = int(os.environ.get("TFG_CRL_HTTP_PORT", "8083"))
CRL_ISSUERS = ("platform", "device", "root")


def _crl_bytes(issuer: str) -> bytes:
    if issuer not in CRL_ISSUERS:
        raise KeyError(issuer)
    return ca_client.crl(issuer)


class _CrlHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        prefix = "/ra/crl/"
        if not self.path.startswith(prefix) or self.path[len(prefix):] not in CRL_ISSUERS:
            self.send_error(404)
            return
        body = _crl_bytes(self.path[len(prefix):])
        self.send_response(200)
        self.send_header("Content-Type", "application/pkix-crl")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve_crl_over_http() -> ThreadingHTTPServer | None:
    """The CRL is signed, so it needs no TLS, and fetching it must not depend on a TLS
    check that could itself need the CRL. This listener serves the CRLs and nothing else."""
    try:
        server = ThreadingHTTPServer(("0.0.0.0", CRL_HTTP_PORT), _CrlHandler)
    except OSError as e:
        print(f"[ra] CRL over HTTP not started on :{CRL_HTTP_PORT}: {e}")
        return None
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@asynccontextmanager
async def lifespan(app: FastAPI):
    ra_service.initialize()
    crl_http = _serve_crl_over_http()
    print(f"[ra] RA loaded (no key); CRLs also served over HTTP on :{CRL_HTTP_PORT}")
    yield
    if crl_http:
        crl_http.shutdown()


app = FastAPI(title="Registration Authority (RA)", version="0.4.0", lifespan=lifespan)


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "service": "ra"}


@app.get("/ra/certificate")
def ra_certificate() -> dict:
    """The trust anchor, plus the issuing certificates a verifier may need to build a path."""
    return {"certificate": ra_service.root_pem(), "issuing": ra_service.issuing_pems()}


class CsrRequest(BaseModel):
    csr: str  # PEM-encoded PKCS#10 certificate signing request


@app.post("/ra/issue")
def ra_issue(req: CsrRequest) -> dict:
    try:
        ra_service.refuse_requested_role(req.csr)
        return ra_service.issue_from_csr(req.csr)
    except ra_service.InvalidCSR as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ca_client.Refused as e:
        raise HTTPException(status_code=e.status, detail=e.detail)


class RevocationRequest(BaseModel):
    request: str  # compact JWS signed by the operator, naming the serial


@app.post("/ra/revoke")
def ra_revoke(req: RevocationRequest) -> dict:
    try:
        order = ra_service.verify_revocation_request(req.request)
        done = ca_client.revoke(order["serial"], order["reason"], order["requested_by"])
    except ra_service.InvalidRequest as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ra_service.NotOperator as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ca_client.Refused as e:
        raise HTTPException(status_code=e.status, detail=e.detail)
    return {**done, "reason": order["reason"], "requested_by": order["requested_by"]}


@app.get("/ra/crl/{issuer}")
def ra_crl(issuer: str) -> Response:
    try:
        return Response(content=_crl_bytes(issuer), media_type="application/pkix-crl")
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown issuer")


class RenewalRequest(BaseModel):
    request: str  # compact JWS signed with the CURRENT key, carrying a CSR for the new one


@app.post("/ra/renew")
def ra_renew(req: RenewalRequest) -> dict:
    try:
        return ra_service.renew_from_request(req.request)
    except (ra_service.InvalidRequest, ra_service.InvalidCSR) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ca_client.Refused as e:
        raise HTTPException(status_code=e.status, detail=e.detail)
