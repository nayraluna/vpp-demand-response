import io
import os
import socket
import sys
import threading
import time
from pathlib import Path

from contextlib import asynccontextmanager

import segno
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import hsm  # noqa: E402

from . import activation_service, pairing_service  # noqa: E402


def _poll_loop() -> None:
    """Periodic outbound polling (design: 'periodic polling of the VTN')."""
    while True:
        override = os.environ.get("TFG_POLL_SECONDS")
        interval = int(override) if override else activation_service.poll_seconds()
        time.sleep(interval)
        try:
            outcome = activation_service.run_cycle()
        except Exception as e:  # VPP unreachable, etc.: keep polling
            print(f"[appliance] poll cycle failed: {e}")
            continue
        calendar = outcome.get("calendar") if outcome else None
        if outcome and (outcome["executed"] or outcome["refused"]
                        or outcome["evidence"]["submitted"]
                        or (calendar and calendar["status"] != "current")):
            print(f"[appliance] poll cycle: {outcome}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    hsm.initialize()
    cfg = pairing_service.config()
    print(f"[appliance] HSM identity: {hsm.subject()} "
          f"(certified P={hsm.nominal_power()} W), state={cfg['state']}")
    if os.environ.get("TFG_POLL_SECONDS") == "0":
        print("[appliance] periodic polling disabled (TFG_POLL_SECONDS=0)")
    else:
        threading.Thread(target=_poll_loop, daemon=True,
                         name="ven-poll-loop").start()
        print("[appliance] periodic VTN polling active "
              f"(every {os.environ.get('TFG_POLL_SECONDS') or activation_service.poll_seconds()} s)")
    yield


app = FastAPI(title="Appliance (VEN) pairing", version="0.2.0", lifespan=lifespan)


@app.get("/ping")
def ping() -> dict:
    return {"status": "ok", "service": "appliance",
            "state": pairing_service.config()["state"]}


PAIRING_PORT = 8082  # must match the port this service is started on


def _local_ip() -> str:
    """The appliance's own address on the home network (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


@app.get("/qr")
def pairing_qr() -> Response:
    """The QR that in production is printed on the appliance: it encodes how to
    reach this pairing interface over the home network, so the user never types
    addresses (requirement U2). The prototype has the appliance serve it."""
    url = f"http://{_local_ip()}:{PAIRING_PORT}"
    buf = io.BytesIO()
    # border=4 is the quiet zone the QR standard requires; scanners rely on it.
    segno.make(url, error="m").save(buf, kind="png", scale=8, border=4)
    return Response(content=buf.getvalue(), media_type="image/png",
                    headers={"X-Pairing-Url": url})


class PairRequest(BaseModel):
    jws: str  # compact JWS: the user-signed onboarding bundle


@app.post("/pair")
def pair(req: PairRequest) -> dict:
    try:
        return {"status": "paired", **pairing_service.pair(req.jws)}
    except pairing_service.InvalidBundle as e:
        raise HTTPException(status_code=400, detail=str(e))
    except pairing_service.AlreadyPaired as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.get("/config")
def config() -> dict:
    return pairing_service.config()


@app.post("/factory-reset")
def factory_reset() -> dict:
    return pairing_service.factory_reset()


@app.post("/poll")
def poll() -> dict:
    """Poll the VPP for activations and act on them (operational step 3)."""
    try:
        return activation_service.poll_and_process()
    except activation_service.NotConfigured as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.post("/evidence")
def submit_evidence() -> dict:
    """Sign in the HSM and submit evidence of the curtailments performed."""
    try:
        return activation_service.submit_evidence()
    except activation_service.NotConfigured as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.get("/status")
def status() -> dict:
    return activation_service.status()
