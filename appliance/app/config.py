import json
import os
from pathlib import Path

CONFIG_FILE = Path(__file__).resolve().parent.parent / "config.json"

FACTORY_DEFAULTS = {
    "state": 0,          # 0 = new (pairing mode), 1 = configured
    "max": 120,          # minutes
    "rec": 30,           # minutes
    "vpp_url": None,     # filled at pairing
    "vpp_mtls_url": None,
    "owner": None,       # subject of the user who paired the appliance
    "paired_at": None,
    "ra_cert_file": None,   # trust anchor used when calling the VPP
    "vpp_cert_file": None,
    # Operational state
    "registration": None,       # VEN registration with the VTN (ids + poll freq)
    "availability": None,       # owner-signed weekly calendar, adopted via polling
    "availability_version": 0,  # monotonic version of the adopted calendar
    "processed": [],            # activation ids already handled (replay protection)
    "seen_nonces": [],          # nonces already seen  (replay protection)
    "last_activation": None,    # what the appliance is currently doing
    "history": [],              # activations executed, for the evidence step
    "submitted": [],            # activations whose evidence the VPP accepted
}


def load() -> dict:
    if not CONFIG_FILE.exists():
        save(dict(FACTORY_DEFAULTS))
    return json.loads(CONFIG_FILE.read_text())


def save(config: dict) -> None:
    # Atomic replace: this file holds the appliance's whole state, including
    # the replay-protection lists, so a crash mid-write must not corrupt it.
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(config, indent=2) + "\n")
    os.replace(tmp, CONFIG_FILE)


def factory_reset() -> dict:
    """Back to state 0 (pairing mode), as after a factory reset."""
    config = dict(FACTORY_DEFAULTS)
    save(config)
    return config
