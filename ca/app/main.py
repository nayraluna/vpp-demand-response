from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import ra_service, registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    ra_service.initialize()
    print("[ca] CA loaded; ready to issue certificates")
    yield


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
    if registry.revoke(serial, order["reason"]):
        return {"revoked": serial, "reason": order["reason"],
                "requested_by": order["requested_by"],
                "crl_number": registry.crl_number()}
    known = registry.lookup(serial)
    if known is None:
        raise HTTPException(status_code=404, detail="serial not issued by this CA")
    raise HTTPException(status_code=409,
                        detail=f"already revoked at {known['revoked_at']}")


@app.get("/ra/crl")
def ra_crl() -> dict:
    return {"crl": ra_service.crl_jws()}


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
