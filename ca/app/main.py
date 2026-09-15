from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import ra_service


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
