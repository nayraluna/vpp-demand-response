import datetime
from contextlib import asynccontextmanager

from cryptography import x509
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import crypto_service, db, revocation


@asynccontextmanager
async def lifespan(app: FastAPI):
    crypto_service.initialize()
    db.initialize()
    print(f"[vpp] identity loaded: {crypto_service.subject()}")
    yield


app = FastAPI(title="VPP (VTN)", version="0.3.0", lifespan=lifespan)


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "service": "vpp"}


class EnrollRequest(BaseModel):
    certificate: str  # PEM issued by the RA


@app.post("/enroll")
def enroll(req: EnrollRequest) -> dict:
    """Create the account for a CA-issued certificate; later requests use it over mTLS."""
    try:
        cert = x509.load_pem_x509_certificate(req.certificate.encode())
    except Exception:
        raise HTTPException(status_code=400, detail="invalid certificate PEM")
    if not crypto_service.issued_by_ca(cert):
        raise HTTPException(status_code=403, detail="certificate not issued by the CA")
    if not crypto_service.within_validity(cert):
        raise HTTPException(status_code=403, detail="certificate expired or not yet valid")
    try:
        if revocation.is_revoked(cert):
            raise HTTPException(status_code=403, detail="certificate revoked")
    except revocation.Unavailable as e:
        raise HTTPException(status_code=503, detail=str(e))

    subject = cert.subject.rfc4514_string()
    existing = db.get_user(subject)
    already = existing is not None
    if already and existing["cert_pem"] != req.certificate:
        # Another certificate may take the account only once the old one is revoked or expired.
        old = x509.load_pem_x509_certificate(existing["cert_pem"].encode())
        try:
            if crypto_service.within_validity(old) and not revocation.is_revoked(old):
                raise HTTPException(status_code=409,
                                    detail="subject already enrolled with a different live certificate")
        except revocation.Unavailable as e:
            raise HTTPException(status_code=503, detail=str(e))
    db.add_user(subject, req.certificate,
                datetime.datetime.now(datetime.timezone.utc).isoformat())
    return {
        "status": "already-enrolled" if already else "enrolled",
        "user": subject,
        "vpp_certificate": crypto_service.certificate_pem(),
    }
