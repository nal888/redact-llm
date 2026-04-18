"""Shared pytest fixtures for the redact-llm test suite.

Contract:
  * All tests run under engagement id ``pytest-suite``.
  * The vault + audit SQLite files live under a tmp_path_factory-owned
    directory, never under the user's ~/.anon-proxy (which would poison
    real engagements).
  * Vault + audit are wiped between tests so ordering never matters.

Because ``anon_proxy.config`` caches env vars at import time, we set the
environment **before** importing any anon_proxy modules.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Environment must be configured before anon_proxy is imported anywhere.
# pytest loads conftest.py before collecting tests, so this runs first.
# ---------------------------------------------------------------------------
_TMP_VAULT_DIR = Path(tempfile.mkdtemp(prefix="redact-llm-pytest-"))
os.environ["ENGAGEMENT_ID"] = "pytest-suite"
os.environ["VAULT_DIR"] = str(_TMP_VAULT_DIR)

# Make the project importable without installing it.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Import after env is configured.
from anon_proxy import audit, config, vault  # noqa: E402


def _wipe_audit() -> None:
    """Empty both audit tables without dropping the DB."""
    with audit._locked() as db:
        db.execute("DELETE FROM events")
        db.execute("DELETE FROM requests")


@pytest.fixture(autouse=True)
def _clean_state():
    """Wipe vault + audit before and after every test."""
    vault.clear()
    _wipe_audit()
    yield
    vault.clear()
    _wipe_audit()


@pytest.fixture
def vault_dir() -> Path:
    return config.VAULT_DIR


@pytest.fixture
def engagement_id() -> str:
    return config.ENGAGEMENT_ID
