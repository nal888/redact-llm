"""Tests for anon_proxy.vault — CRUD contract for real ↔ surrogate mappings."""
from __future__ import annotations

from anon_proxy import vault


def test_upsert_then_lookup_roundtrip():
    vault.upsert("IPV4", "10.1.2.3", "203.0.113.7")
    assert vault.surrogate_for("IPV4", "10.1.2.3") == "203.0.113.7"


def test_real_for_reverse_lookup():
    vault.upsert("EMAIL", "alice@acme.com", "a1b2c3d4@example.pentest")
    got = vault.real_for("a1b2c3d4@example.pentest")
    assert got == ("EMAIL", "alice@acme.com")


def test_surrogate_for_returns_none_when_missing():
    assert vault.surrogate_for("IPV4", "192.168.99.99") is None


def test_real_for_returns_none_when_missing():
    assert vault.real_for("nonexistent.surrogate.value") is None


def test_upsert_is_idempotent():
    """INSERT OR IGNORE: same (type, real) inserted twice keeps first surrogate."""
    vault.upsert("DOMAIN", "corp.acme.com", "first.pentest.local")
    vault.upsert("DOMAIN", "corp.acme.com", "second.pentest.local")
    assert vault.surrogate_for("DOMAIN", "corp.acme.com") == "first.pentest.local"


def test_all_surrogates_lists_everything():
    vault.upsert("IPV4", "10.1.2.3", "203.0.113.7")
    vault.upsert("EMAIL", "bob@x.com", "bob@example.pentest")
    rows = vault.all_surrogates()
    assert len(rows) == 2
    as_set = {(t, r, s) for t, r, s in rows}
    assert ("IPV4", "10.1.2.3", "203.0.113.7") in as_set
    assert ("EMAIL", "bob@x.com", "bob@example.pentest") in as_set


def test_clear_wipes_everything():
    vault.upsert("IPV4", "10.1.2.3", "203.0.113.7")
    vault.upsert("EMAIL", "bob@x.com", "bob@example.pentest")
    vault.clear()
    assert vault.all_surrogates() == []
    assert vault.surrogate_for("IPV4", "10.1.2.3") is None


def test_same_real_different_types_are_independent():
    """(entity_type, real) is the composite key, not just real."""
    vault.upsert("IPV4", "1234", "ip-sur")
    vault.upsert("MD5", "1234", "md5-sur")
    assert vault.surrogate_for("IPV4", "1234") == "ip-sur"
    assert vault.surrogate_for("MD5", "1234") == "md5-sur"


def test_stats_includes_engagement_id_and_counts():
    vault.upsert("IPV4", "10.0.0.1", "203.0.113.1")
    vault.upsert("IPV4", "10.0.0.2", "203.0.113.2")
    vault.upsert("DOMAIN", "x.corp", "a.pentest.local")
    s = vault.stats()
    assert s["engagement_id"] == "pytest-suite"
    assert s["counts"].get("IPV4") == 2
    assert s["counts"].get("DOMAIN") == 1
