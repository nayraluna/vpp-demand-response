import datetime
import re
import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent.parent / "ca.db"


def _conn() -> sqlite3.Connection:
    return sqlite3.connect(DB_FILE)


def initialize() -> None:
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
        # The register keeps what was issued and who withdrew it, not only that it happened.
        for column in ("certificate TEXT", "profile TEXT", "revoked_by TEXT"):
            try:
                c.execute(f"ALTER TABLE issued ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        c.execute(
            """CREATE TABLE IF NOT EXISTS meta(
                   key   TEXT PRIMARY KEY,
                   value TEXT NOT NULL)"""
        )


def record(serial: str, key_id: str, subject: str,
           issued_at: datetime.datetime, not_after: datetime.datetime,
           certificate: str, profile: str) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO issued(serial, key_id, subject, issued_at, not_after, certificate, profile)"
            " VALUES(?, ?, ?, ?, ?, ?, ?)",
            (serial, key_id, subject, issued_at.isoformat(), not_after.isoformat(),
             certificate, profile),
        )


def normalize_serial(text: str) -> str:
    """Hex as every tool prints it: case, colons, spaces and leading zeros do not matter."""
    s = text.strip().lower().replace(":", "").replace(" ", "")
    s = s[2:] if s.startswith("0x") else s
    if not re.fullmatch(r"[0-9a-f]+", s):
        raise ValueError(f"serial is not hexadecimal: {text!r}")
    return s.lstrip("0") or "0"


def serial_for_key(key_id: str) -> str | None:
    with _conn() as c:
        row = c.execute(
            "SELECT serial FROM issued WHERE key_id=? LIMIT 1", (key_id,)
        ).fetchone()
    return row[0] if row else None


def live_serial_for_subject(subject: str, now: datetime.datetime) -> str | None:
    """Serial of the subject's certificate that is neither revoked nor expired, if any."""
    with _conn() as c:
        row = c.execute(
            "SELECT serial FROM issued WHERE subject=? AND revoked_at IS NULL"
            " AND not_after > ? ORDER BY issued_at DESC LIMIT 1",
            (subject, now.isoformat()),
        ).fetchone()
    return row[0] if row else None


def lookup(serial: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT serial, subject, not_after, revoked_at, reason, revoked_by, profile, certificate"
            " FROM issued WHERE serial=?", (serial,)
        ).fetchone()
    if not row:
        return None
    return {"serial": row[0], "subject": row[1], "not_after": row[2],
            "revoked_at": row[3], "reason": row[4], "revoked_by": row[5],
            "profile": row[6], "certificate": row[7]}


def revoke(serial: str, reason: str, by: str | None = None,
           when: datetime.datetime | None = None) -> bool:
    """False if the serial was never issued here or was already revoked."""
    when = when or datetime.datetime.now(datetime.timezone.utc)
    with _conn() as c:
        changed = c.execute(
            "UPDATE issued SET revoked_at=?, reason=?, revoked_by=?"
            " WHERE serial=? AND revoked_at IS NULL",
            (when.isoformat(), reason, by, serial),
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
    """Revoked certificates not yet expired; expired ones drop out so the list does not grow."""
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
    """Monotonic, bumped on every revocation, so a relying party can refuse a list older than its own."""
    with _conn() as c:
        row = c.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()
    return int(row[0]) if row else 0


def _bump_crl_number(c: sqlite3.Connection) -> int:
    # Uses the caller's connection so the bump commits together with the revocation that caused it.
    row = c.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()
    n = (int(row[0]) if row else 0) + 1
    c.execute("INSERT INTO meta(key, value) VALUES('crl_number', ?)"
              " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(n),))
    return n
