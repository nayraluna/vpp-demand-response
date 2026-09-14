import json
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent.parent / "vpp.db"


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_FILE)


def initialize() -> None:
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS users(
                   subject     TEXT PRIMARY KEY,
                   cert_pem    TEXT NOT NULL,
                   enrolled_at TEXT NOT NULL)"""
        )
        # Activations issued to appliances. Written when a DR event is issued
        # (step 3); read by participant selection to enforce recovery time.
        c.execute(
            """CREATE TABLE IF NOT EXISTS activations(
                   activation_id TEXT PRIMARY KEY,
                   ven_subject   TEXT NOT NULL,
                   day           TEXT NOT NULL,
                   slot_start    INTEGER NOT NULL,
                   slot_end      INTEGER NOT NULL,
                   action        TEXT NOT NULL,
                   nonce         TEXT NOT NULL,
                   issued_at     TEXT NOT NULL,
                   ends_at       TEXT,
                   delivered_at  TEXT)"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS vens(
                   ven_subject     TEXT PRIMARY KEY,
                   ven_id          TEXT NOT NULL,
                   registration_id TEXT NOT NULL,
                   ven_name        TEXT,
                   profile         TEXT,
                   registered_at   TEXT NOT NULL)"""
        )
        # Ownership recorded from the owner proof. The appliance certificate is
        # kept (it verifies the appliance's future messages) together with the
        # ownership relation and the declared parameters; the proof SIGNATURE is
        # verified on arrival and then discarded - it only establishes the bind.
        c.execute(
            """CREATE TABLE IF NOT EXISTS appliances(
                   ven_subject   TEXT PRIMARY KEY,
                   owner         TEXT NOT NULL,
                   cert_pem      TEXT NOT NULL,
                   nominal_power INTEGER NOT NULL,
                   max_curtail   INTEGER NOT NULL,
                   recovery      INTEGER NOT NULL,
                   bound_at      TEXT NOT NULL)"""
        )
        # Participation evidence. Unlike the owner proof, whose signature is
        # discarded once it has established the binding, HERE THE SIGNATURE IS
        # THE RECORD: it is what allows the participation to be audited and
        # remunerated afterwards (Design, Data Architecture).
        c.execute(
            """CREATE TABLE IF NOT EXISTS evidence(
                   activation_id TEXT PRIMARY KEY,
                   ven_subject   TEXT NOT NULL,
                   executed_at   TEXT NOT NULL,
                   reduction_pct INTEGER NOT NULL,
                   jws           TEXT NOT NULL,
                   verified_at   TEXT NOT NULL)"""
        )
        # Operational data: the weekly availability calendar declared by the
        # user, stored as semi-structured JSON (Design, Data Architecture).
        # Alongside the parsed slots (used by participant selection), the row
        # keeps the owner-signed JWS verbatim and its version: the appliance
        # retrieves the signed artefact through its outbound polling and
        # enforces the signature and the monotonic version itself.
        c.execute(
            """CREATE TABLE IF NOT EXISTS availability(
                   ven_subject TEXT PRIMARY KEY,
                   slots       TEXT NOT NULL,
                   updated_at  TEXT NOT NULL)"""
        )
        for column, decl in (("jws", "TEXT"), ("version", "INTEGER")):
            try:
                c.execute(f"ALTER TABLE availability ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError:
                pass  # column already present


def get_user(subject: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT subject, cert_pem, enrolled_at FROM users WHERE subject=?",
            (subject,),
        ).fetchone()
    return {"subject": row[0], "cert_pem": row[1], "enrolled_at": row[2]} if row else None


def add_user(subject: str, cert_pem: str, enrolled_at: str) -> None:
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO users(subject, cert_pem, enrolled_at) VALUES(?,?,?)",
            (subject, cert_pem, enrolled_at),
        )


def get_registration(ven_subject: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            """SELECT ven_subject, ven_id, registration_id, ven_name, profile,
                      registered_at FROM vens WHERE ven_subject=?""",
            (ven_subject,),
        ).fetchone()
    if not row:
        return None
    return {"ven_subject": row[0], "ven_id": row[1], "registration_id": row[2],
            "ven_name": row[3], "profile": row[4], "registered_at": row[5]}


def get_appliance(ven_subject: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            """SELECT ven_subject, owner, cert_pem, nominal_power, max_curtail,
                      recovery, bound_at FROM appliances WHERE ven_subject=?""",
            (ven_subject,),
        ).fetchone()
    if not row:
        return None
    return {"ven_subject": row[0], "owner": row[1], "cert_pem": row[2],
            "nominal_power": row[3], "max_curtail": row[4], "recovery": row[5],
            "bound_at": row[6]}


def add_appliance(ven_subject: str, owner: str, cert_pem: str,
                  nominal_power: int, max_curtail: int, recovery: int,
                  bound_at: str) -> None:
    with _conn() as c:
        c.execute(
            """INSERT OR REPLACE INTO appliances(ven_subject, owner, cert_pem,
                   nominal_power, max_curtail, recovery, bound_at)
               VALUES(?,?,?,?,?,?,?)""",
            (ven_subject, owner, cert_pem, nominal_power, max_curtail, recovery,
             bound_at),
        )


def list_appliances_by_owner(owner: str) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            """SELECT ven_subject, nominal_power, max_curtail, recovery
               FROM appliances WHERE owner=? ORDER BY ven_subject""",
            (owner,),
        ).fetchall()
    return [{"ven_subject": r[0], "nominal_power": r[1],
             "max_curtail": r[2], "recovery": r[3]} for r in rows]


def add_activation(activation: dict) -> None:
    with _conn() as c:
        c.execute(
            """INSERT INTO activations(activation_id, ven_subject, day, slot_start,
                   slot_end, action, nonce, issued_at, ends_at, delivered_at)
               VALUES(?,?,?,?,?,?,?,?,?,NULL)""",
            (activation["activation_id"], activation["ven_subject"],
             activation["day"], activation["slot_start"], activation["slot_end"],
             activation["action"], activation["nonce"], activation["issued_at"],
             activation["ends_at"]),
        )


def pending_activations(ven_subject: str) -> list[dict]:
    """Activations issued to this appliance that it has not yet retrieved."""
    with _conn() as c:
        rows = c.execute(
            """SELECT activation_id, day, slot_start, slot_end, action, nonce,
                      issued_at, ends_at
               FROM activations
               WHERE ven_subject=? AND delivered_at IS NULL
               ORDER BY issued_at""",
            (ven_subject,),
        ).fetchall()
    return [{"activation_id": r[0], "day": r[1], "slot_start": r[2],
             "slot_end": r[3], "action": r[4], "nonce": r[5],
             "issued_at": r[6], "ends_at": r[7]} for r in rows]


def mark_delivered(activation_id: str, delivered_at: str) -> None:
    with _conn() as c:
        c.execute("UPDATE activations SET delivered_at=? WHERE activation_id=?",
                  (delivered_at, activation_id))


def get_activation(activation_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            """SELECT activation_id, ven_subject, day, slot_start, slot_end,
                      action, nonce, issued_at, ends_at, delivered_at
               FROM activations WHERE activation_id=?""",
            (activation_id,),
        ).fetchone()
    if not row:
        return None
    return {"activation_id": row[0], "ven_subject": row[1], "day": row[2],
            "slot_start": row[3], "slot_end": row[4], "action": row[5],
            "nonce": row[6], "issued_at": row[7], "ends_at": row[8],
            "delivered_at": row[9]}


def get_evidence(activation_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            """SELECT activation_id, ven_subject, executed_at, reduction_pct,
                      jws, verified_at FROM evidence WHERE activation_id=?""",
            (activation_id,),
        ).fetchone()
    if not row:
        return None
    return {"activation_id": row[0], "ven_subject": row[1], "executed_at": row[2],
            "reduction_pct": row[3], "jws": row[4], "verified_at": row[5]}


def add_evidence(activation_id: str, ven_subject: str, executed_at: str,
                 reduction_pct: int, jws: str, verified_at: str) -> None:
    with _conn() as c:
        c.execute(
            """INSERT INTO evidence(activation_id, ven_subject, executed_at,
                   reduction_pct, jws, verified_at) VALUES(?,?,?,?,?,?)""",
            (activation_id, ven_subject, executed_at, reduction_pct, jws, verified_at),
        )


def evidence_for_owner(owner: str) -> list[dict]:
    """Verified participations of every appliance belonging to this user."""
    with _conn() as c:
        rows = c.execute(
            """SELECT e.activation_id, e.ven_subject, e.executed_at,
                      e.reduction_pct, e.verified_at, a.nominal_power,
                      c.day, c.slot_start, c.slot_end, c.action
               FROM evidence e
               JOIN appliances a ON a.ven_subject = e.ven_subject
               JOIN activations c ON c.activation_id = e.activation_id
               WHERE a.owner = ?
               ORDER BY e.executed_at DESC""",
            (owner,),
        ).fetchall()
    return [{"activation_id": r[0], "ven_subject": r[1], "executed_at": r[2],
             "reduction_pct": r[3], "verified_at": r[4], "nominal_power": r[5],
             "day": r[6], "slot_start": r[7], "slot_end": r[8], "action": r[9]}
            for r in rows]


def last_activation_end(ven_subject: str) -> str | None:
    """When this appliance's most recent activation finished (for recovery)."""
    with _conn() as c:
        row = c.execute(
            """SELECT ends_at FROM activations WHERE ven_subject=? AND ends_at IS NOT NULL
               ORDER BY ends_at DESC LIMIT 1""",
            (ven_subject,),
        ).fetchone()
    return row[0] if row else None


def list_appliances_for_selection() -> list[dict]:
    """Every enrolled appliance with the data participant selection needs."""
    with _conn() as c:
        rows = c.execute(
            """SELECT a.ven_subject, a.nominal_power, a.max_curtail, a.recovery,
                      v.slots
               FROM appliances a LEFT JOIN availability v
                 ON v.ven_subject = a.ven_subject
               ORDER BY a.ven_subject"""
        ).fetchall()
    out = []
    for r in rows:
        out.append({"ven_subject": r[0], "nominal_power": r[1],
                    "max_curtail": r[2], "recovery": r[3],
                    "availability": json.loads(r[4]) if r[4] else None,
                    "last_activation_end": last_activation_end(r[0])})
    return out


def get_availability(ven_subject: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            """SELECT slots, updated_at, jws, version
               FROM availability WHERE ven_subject=?""",
            (ven_subject,),
        ).fetchone()
    if not row:
        return None
    return {"slots": json.loads(row[0]), "updated_at": row[1],
            "jws": row[2], "version": row[3]}


def set_availability(ven_subject: str, slots: dict, updated_at: str,
                     jws: str | None = None, version: int | None = None) -> None:
    with _conn() as c:
        c.execute(
            """INSERT OR REPLACE INTO availability(ven_subject, slots, updated_at,
                   jws, version)
               VALUES(?,?,?,?,?)""",
            (ven_subject, json.dumps(slots), updated_at, jws, version),
        )


def add_registration(ven_subject: str, ven_id: str, registration_id: str,
                     ven_name: str, profile: str, registered_at: str) -> None:
    with _conn() as c:
        c.execute(
            """INSERT OR REPLACE INTO vens(ven_subject, ven_id, registration_id,
                   ven_name, profile, registered_at) VALUES(?,?,?,?,?,?)""",
            (ven_subject, ven_id, registration_id, ven_name, profile, registered_at),
        )
