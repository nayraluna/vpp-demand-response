import json
import os
from pathlib import Path

CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.json"

FACTORY_DEFAULTS = {
    "state": 0,          # 0 = pairing mode, 1 = configured
    "max": 120,          # minutes
    "rec": 30,           # minutes
    "vpp_url": None,
    "vpp_mtls_url": None,
    "owner": None,       # subject of the pairing user
    "owner_serial": None,   # checked against the CRL
    "paired_at": None,
    "vpp_cert_file": None,
    "registration": None,       # VTN ids and poll period
    "availability": None,       # owner-signed weekly calendar
    "availability_version": 0,  # monotonic
    "crl_number": 0,            # monotonic
    "crl_next_update": None,    # list expiry
    "crl_revoked": [],          # serials
    "processed": [],            # activation ids seen, replay protection
    "last_activation": None,
    "history": [],              # executed, pending evidence
    "submitted": [],            # evidence accepted by the VPP
}


def load() -> dict:
    if not CONFIG_FILE.exists():
        save(dict(FACTORY_DEFAULTS))
    return json.loads(CONFIG_FILE.read_text())


def save(config: dict) -> None:
    # Atomic replace: the whole appliance state lives here, a crash mid-write must not corrupt it.
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config, indent=2) + "\n")
    os.replace(tmp, CONFIG_FILE)


def factory_reset() -> dict:
    config = dict(FACTORY_DEFAULTS)
    save(config)
    return config
