"""SQLite vault — real ↔ surrogate mappings, isolated per engagement.

The vault contains real (client) values in plaintext — it must, so we can
deanonymize responses. On creation the SQLite files (including WAL sidecars)
are chmod'd 0600 so only the owner can read them.
"""
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from . import config

_lock = threading.Lock()


def _tighten_sidecars() -> None:
    """Ensure WAL + SHM sidecar files also have 0600."""
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(config.VAULT_PATH) + suffix)
        if p.exists():
            try:
                p.chmod(0o600)
            except OSError:
                pass


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(config.VAULT_PATH, isolation_level=None, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""
        CREATE TABLE IF NOT EXISTS mappings (
            entity_type TEXT NOT NULL,
            real TEXT NOT NULL,
            surrogate TEXT NOT NULL,
            first_seen REAL NOT NULL DEFAULT (strftime('%s','now')),
            PRIMARY KEY (entity_type, real)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_surrogate ON mappings(surrogate)")
    _tighten_sidecars()
    return c


_db = _conn()


@contextmanager
def _locked():
    with _lock:
        yield _db


def upsert(entity_type: str, real: str, surrogate: str) -> None:
    _tighten_sidecars()
    with _locked() as db:
        db.execute(
            "INSERT OR IGNORE INTO mappings (entity_type, real, surrogate) VALUES (?,?,?)",
            (entity_type, real, surrogate),
        )


def surrogate_for(entity_type: str, real: str) -> str | None:
    with _locked() as db:
        row = db.execute(
            "SELECT surrogate FROM mappings WHERE entity_type=? AND real=?",
            (entity_type, real),
        ).fetchone()
    return row[0] if row else None


def real_for(surrogate: str) -> tuple[str, str] | None:
    """Reverse lookup. Returns (entity_type, real) or None."""
    with _locked() as db:
        row = db.execute(
            "SELECT entity_type, real FROM mappings WHERE surrogate=?",
            (surrogate,),
        ).fetchone()
    return (row[0], row[1]) if row else None


def all_surrogates() -> list[tuple[str, str, str]]:
    with _locked() as db:
        return db.execute("SELECT entity_type, real, surrogate FROM mappings").fetchall()


def clear() -> None:
    with _locked() as db:
        db.execute("DELETE FROM mappings")


def stats() -> dict:
    with _locked() as db:
        rows = db.execute(
            "SELECT entity_type, COUNT(*) FROM mappings GROUP BY entity_type"
        ).fetchall()
    return {"engagement_id": config.ENGAGEMENT_ID, "counts": dict(rows)}
