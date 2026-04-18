"""Append-only audit log — what got anonymized, when, in which request.

Real values are HMAC-hashed (never stored plaintext) so the audit log itself
cannot leak data. The surrogate is stored so you can reconcile with the vault.
"""
import hmac
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from . import config

_AUDIT_PATH = config.VAULT_DIR / f"{config.ENGAGEMENT_ID}.audit.sqlite"
_lock = threading.Lock()


def _tighten_sidecars() -> None:
    """0600 on audit SQLite + WAL/SHM sidecars."""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(_AUDIT_PATH) + suffix)
        if p.exists():
            try:
                p.chmod(0o600)
            except OSError:
                pass


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(_AUDIT_PATH, isolation_level=None, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            request_id TEXT PRIMARY KEY,
            ts REAL NOT NULL,
            engagement_id TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status INTEGER,
            bytes_in INTEGER,
            bytes_out INTEGER,
            entities_found INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            ts REAL NOT NULL,
            entity_type TEXT NOT NULL,
            real_hash TEXT NOT NULL,
            surrogate TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES requests(request_id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_request ON events(request_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(entity_type)")
    _tighten_sidecars()
    return c


_db = _conn()


@contextmanager
def _locked():
    with _lock:
        yield _db


def hash_real(real: str) -> str:
    """HMAC-hash a real value so audit log rows can't leak plaintext."""
    return hmac.new(config.ENGAGEMENT_SECRET, real.encode(), hashlib.sha256).hexdigest()[:16]


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def log_request(request_id: str, method: str, path: str, bytes_in: int) -> None:
    with _locked() as db:
        db.execute(
            "INSERT OR REPLACE INTO requests (request_id, ts, engagement_id, method, path, bytes_in) "
            "VALUES (?,?,?,?,?,?)",
            (request_id, time.time(), config.ENGAGEMENT_ID, method, path, bytes_in),
        )


def log_event(request_id: str, entity_type: str, real: str, surrogate: str) -> None:
    with _locked() as db:
        db.execute(
            "INSERT INTO events (request_id, ts, entity_type, real_hash, surrogate) VALUES (?,?,?,?,?)",
            (request_id, time.time(), entity_type, hash_real(real), surrogate),
        )


def log_response(request_id: str, status: int, bytes_out: int, entities_found: int) -> None:
    with _locked() as db:
        db.execute(
            "UPDATE requests SET status=?, bytes_out=?, entities_found=? WHERE request_id=?",
            (status, bytes_out, entities_found, request_id),
        )


def export_csv() -> str:
    """Export full audit as CSV. Real values remain as hashes."""
    lines = ["ts,request_id,engagement_id,method,path,status,bytes_in,bytes_out,entity_type,real_hash,surrogate"]
    with _locked() as db:
        rows = db.execute("""
            SELECT r.ts, r.request_id, r.engagement_id, r.method, r.path, r.status,
                   r.bytes_in, r.bytes_out, e.entity_type, e.real_hash, e.surrogate
            FROM requests r LEFT JOIN events e ON r.request_id = e.request_id
            ORDER BY r.ts, e.id
        """).fetchall()
    for row in rows:
        lines.append(",".join(str(x if x is not None else "") for x in row))
    return "\n".join(lines)


def stats() -> dict:
    with _locked() as db:
        req_count = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        ev_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_type = dict(db.execute(
            "SELECT entity_type, COUNT(*) FROM events GROUP BY entity_type"
        ).fetchall())
    return {
        "engagement_id": config.ENGAGEMENT_ID,
        "audit_path": str(_AUDIT_PATH),
        "requests_logged": req_count,
        "events_logged": ev_count,
        "events_by_type": by_type,
    }
