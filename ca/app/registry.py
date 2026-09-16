import datetime
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent.parent / "ca.db"


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_FILE)


def initialize() -> None:
    # One row per certificate the CA has issued.
    # CA checks if public key was already enrolled, and if the certificate has been revoked.
    with _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS issued(
                   serial      TEXT PRIMARY KEY,
                   key_id      TEXT NOT NULL,
                   subject     TEXT NOT NULL,
                   issued_at   TEXT NOT NULL,
                   not_after   TEXT NOT NULL,
                   revoked_at  TEXT,
                   reason      TEXT)"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS issued_key_id ON issued(key_id)")


def record(serial: str, key_id: str, subject: str,
           issued_at: datetime.datetime, not_after: datetime.datetime) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO issued(serial, key_id, subject, issued_at, not_after)"
            " VALUES(?, ?, ?, ?, ?)",
            (serial, key_id, subject, issued_at.isoformat(), not_after.isoformat()),
        )


def serial_for_key(key_id: str) -> str | None:
    """The serial already issued for this public key, if there is one."""
    with _conn() as c:
        row = c.execute(
            "SELECT serial FROM issued WHERE key_id=? LIMIT 1", (key_id,)
        ).fetchone()
    return row[0] if row else None


def revoke(serial: str, reason: str,
           when: datetime.datetime | None = None) -> bool:
    """Mark a certificate revoked.
    False if the serial was never issued here or was already revoked."""
    when = when or datetime.datetime.now(datetime.timezone.utc)
    with _conn() as c:
        changed = c.execute(
            "UPDATE issued SET revoked_at=?, reason=?"
            " WHERE serial=? AND revoked_at IS NULL",
            (when.isoformat(), reason, serial),
        ).rowcount
    return changed == 1


def is_revoked(serial: str) -> bool:
    with _conn() as c:
        row = c.execute(
            "SELECT revoked_at FROM issued WHERE serial=?", (serial,)
        ).fetchone()
    return bool(row and row[0])


def revoked(now: datetime.datetime | None = None) -> list[dict]:
    """CRL has the revoked certificates that had not expired yet.
    Expired ones drop out on their own (to stop the list from growing)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    with _conn() as c:
        rows = c.execute(
            "SELECT serial, revoked_at, reason, not_after FROM issued"
            " WHERE revoked_at IS NOT NULL AND not_after > ?"
            " ORDER BY revoked_at",
            (now.isoformat(),),
        ).fetchall()
    return [{"serial": r[0], "revoked_at": r[1], "reason": r[2]} for r in rows]
