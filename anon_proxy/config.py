"""Runtime configuration — engagement id + secret for per-engagement isolation.

Security notes:
  - VAULT_DIR is created with mode 0700 (owner-only) so other local users
    can't list engagement names or read vault files.
  - Secret file is created atomically with mode 0600 (no race window where
    it exists world-readable before chmod).
  - Existing files have their permissions tightened on startup if lax.
"""
import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger("anon-proxy.config")

ENGAGEMENT_ID = os.environ.get("ENGAGEMENT_ID", "default")
VAULT_DIR = Path(os.environ.get("VAULT_DIR", str(Path.home() / ".anon-proxy"))).expanduser()
VAULT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
# mkdir mode only applies when the dir is created; tighten in case it already existed.
try:
    VAULT_DIR.chmod(0o700)
except OSError:
    pass

VAULT_PATH = VAULT_DIR / f"{ENGAGEMENT_ID}.sqlite"
SECRET_PATH = VAULT_DIR / f"{ENGAGEMENT_ID}.key"

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "https://api.anthropic.com")
PORT = int(os.environ.get("PORT", "8080"))
WORDLIST_PATH = os.environ.get("WORDLIST_PATH", "")


def _tighten_perms(path: Path, mode: int = 0o600) -> None:
    """chmod to `mode` if the file exists and has wider permissions. Warn if originally lax."""
    if not path.exists():
        return
    try:
        cur = path.stat().st_mode & 0o777
        if cur != mode:
            if cur & 0o077:  # any group/other bits set
                log.warning(
                    f"tightening permissions on {path} "
                    f"from {oct(cur)} to {oct(mode)} (was readable by others)"
                )
            path.chmod(mode)
    except OSError as e:
        log.warning(f"could not chmod {path}: {e}")


def _load_or_create_secret() -> bytes:
    """Load existing HMAC secret or generate a new one.

    Creates with mode 0600 atomically (O_CREAT | O_EXCL) to avoid the
    tiny window where a file exists with default umask before chmod runs.
    """
    if SECRET_PATH.exists():
        _tighten_perms(SECRET_PATH, 0o600)
        return SECRET_PATH.read_bytes()
    key = secrets.token_bytes(32)
    # Atomic create with 0o600 — no race.
    fd = os.open(str(SECRET_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    return key


ENGAGEMENT_SECRET: bytes = _load_or_create_secret()

# Tighten any pre-existing per-engagement files. Safe to call even if they
# don't exist yet — no-op in that case. Covers the three file types we create:
#   <engagement>.sqlite         (vault)
#   <engagement>.sqlite-shm     (SQLite WAL shared memory)
#   <engagement>.sqlite-wal     (SQLite WAL)
#   <engagement>.audit.sqlite   (audit log)
#   <engagement>.audit.sqlite-shm / -wal
for p in VAULT_DIR.glob(f"{ENGAGEMENT_ID}*"):
    if p.is_file():
        _tighten_perms(p, 0o600)
