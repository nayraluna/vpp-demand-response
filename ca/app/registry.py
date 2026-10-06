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
        # Small key/value store. Today it holds one thing, the CRL number.
        c.execute(
            """CREATE TABLE IF NOT EXISTS meta(
                   key   TEXT PRIMARY KEY,
                   value TEXT NOT NULL)"""
        )


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


def lookup(serial: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT serial, subject, not_after, revoked_at, reason FROM issued"
            " WHERE serial=?", (serial,)
        ).fetchone()
    if not row:
        return None
    return {"serial": row[0], "subject": row[1], "not_after": row[2],
            "revoked_at": row[3], "reason": row[4]}


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
        if changed == 1:
            _bump_crl_number(c)
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


def crl_number() -> int:
    """Monotonic counter, bumped on every revocation. The same role the version
    plays in the availability calendar: a relying party refuses a list older
    than the one it already holds."""
    with _conn() as c:
        row = c.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()
    return int(row[0]) if row else 0


def _bump_crl_number(c: sqlite3.Connection) -> int:
    # Takes the caller's connection so the bump commits together with the
    # revocation that caused it. Done separately, one could land without the
    # other.
    row = c.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()
    n = (int(row[0]) if row else 0) + 1
    c.execute("INSERT INTO meta(key, value) VALUES('crl_number', ?)"
              " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(n),))
    return n
