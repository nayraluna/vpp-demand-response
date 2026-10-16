"""The CA process: holds the issuing keys, listens on loopback only, signs what the RA validated.

    python -m uvicorn app.ca_main:app --host 127.0.0.1 --port 8084
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from cryptography import x509

from . import ca_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    ca_service.initialize()
    print("[ca] issuing CAs loaded: " + ", ".join(ca_service.ISSUERS))
    yield


app = FastAPI(title="Certification Authority (issuing CAs)", version="0.4.0", lifespan=lifespan)


class SignRequest(BaseModel):
    csr: str
    profile: str = "client"
    san: list[str] | None = None
    days: int = 365
    supersedes: str | None = None


@app.post("/sign")
def sign(req: SignRequest) -> dict:
    """Online issuance is platform credentials only. Device identities are certified at the factory."""
    if req.profile not in ca_service.PROFILES:
        raise HTTPException(status_code=400, detail=f"unknown certificate profile {req.profile!r}")
    try:
        csr = x509.load_pem_x509_csr(req.csr.encode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"could not parse CSR: {e}")
    try:
        return ca_service.ISSUERS["platform"].sign_leaf(csr, req.profile, req.san, req.days, req.supersedes)
    except ca_service.AlreadyEnrolled as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


class RevokeRequest(BaseModel):
    serial: str
    reason: str
    by: str


@app.post("/revoke")
def revoke(req: RevokeRequest) -> dict:
    """Either issuing CA may hold the serial: the one that issued it withdraws it."""
    for issuer in ca_service.ISSUERS.values():
        known = issuer.register.lookup(req.serial)
        if known is None:
            continue
        if issuer.revoke(req.serial, req.reason, req.by):
            return {"revoked": req.serial, "issuer": issuer.name,
                    "crl_number": issuer.register.crl_number()}
        raise HTTPException(status_code=409, detail=f"already revoked at {known['revoked_at']}")
    raise HTTPException(status_code=404, detail="serial not issued by this CA")


@app.get("/crl/{issuer}")
def crl(issuer: str) -> Response:
    if issuer == "root":
        return Response(content=ca_service.root_crl_der(), media_type="application/pkix-crl")
    if issuer not in ca_service.ISSUERS:
        raise HTTPException(status_code=404, detail="unknown issuer")
    return Response(content=ca_service.ISSUERS[issuer].crl_der(), media_type="application/pkix-crl")


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "service": "ca"}
