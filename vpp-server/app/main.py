import datetime
from contextlib import asynccontextmanager

from cryptography import x509
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import crypto_service, db


@asynccontextmanager
async def lifespan(app: FastAPI):
    crypto_service.initialize()
    db.initialize()
    print(f"[vpp] signing identity loaded: {crypto_service.subject()}")
    yield


app = FastAPI(title="VPP (VTN)", version="0.3.0", lifespan=lifespan)


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "service": "vpp"}


class EnrollRequest(BaseModel):
    certificate: str  # the user's certificate (PEM), issued by the RA


@app.post("/enroll")
def enroll(req: EnrollRequest) -> dict:
    """Step 8a - App->VPP: create a user account.

    First contact is over normal TLS; the user presents the certificate the RA
    issued for them. The VPP accepts it only if the RA signed it, stores the
    account, and returns Cert_VPP. From here on the user authenticates over
    mutual TLS with this same certificate.
    """
    try:
        cert = x509.load_pem_x509_certificate(req.certificate.encode())
    except Exception:
        raise HTTPException(status_code=400, detail="invalid certificate PEM")
    if not crypto_service.issued_by_ra(cert):
        raise HTTPException(status_code=403, detail="certificate not issued by the RA")

    subject = cert.subject.rfc4514_string()
    already = db.get_user(subject) is not None
    db.add_user(subject, req.certificate,
                datetime.datetime.now(datetime.timezone.utc).isoformat())
    return {
        "status": "already-enrolled" if already else "enrolled",
        "user": subject,
        "vpp_certificate": crypto_service.certificate_pem(),
    }
