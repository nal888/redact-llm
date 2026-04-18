"""Tests for anon_proxy.audit — append-only request/event log."""
from __future__ import annotations

from anon_proxy import audit


def test_log_request_creates_row():
    rid = audit.new_request_id()
    audit.log_request(rid, "POST", "/v1/messages", 1234)
    with audit._locked() as db:
        row = db.execute(
            "SELECT request_id, method, path, bytes_in FROM requests WHERE request_id=?",
            (rid,),
        ).fetchone()
    assert row == (rid, "POST", "/v1/messages", 1234)


def test_log_event_hashes_real_value():
    rid = audit.new_request_id()
    audit.log_request(rid, "POST", "/v1/messages", 10)
    real = "10.1.2.3"
    audit.log_event(rid, "IPV4", real, "203.0.113.7")

    with audit._locked() as db:
        row = db.execute(
            "SELECT entity_type, real_hash, surrogate FROM events WHERE request_id=?",
            (rid,),
        ).fetchone()

    entity_type, real_hash, surrogate = row
    assert entity_type == "IPV4"
    assert surrogate == "203.0.113.7"
    # Critical: the real value must never appear in plaintext.
    assert real_hash != real
    assert real not in real_hash
    # But the hash is deterministic — so we can reconcile externally.
    assert real_hash == audit.hash_real(real)


def test_hash_real_is_deterministic_and_not_plaintext():
    h1 = audit.hash_real("sensitive-value")
    h2 = audit.hash_real("sensitive-value")
    assert h1 == h2
    assert "sensitive-value" not in h1


def test_log_response_updates_status_and_counts():
    rid = audit.new_request_id()
    audit.log_request(rid, "POST", "/v1/messages", 100)
    audit.log_response(rid, 200, 500, 7)
    with audit._locked() as db:
        row = db.execute(
            "SELECT status, bytes_out, entities_found FROM requests WHERE request_id=?",
            (rid,),
        ).fetchone()
    assert row == (200, 500, 7)


def test_full_request_lifecycle_creates_proper_records():
    rid = audit.new_request_id()
    audit.log_request(rid, "POST", "/v1/messages", 1024)
    audit.log_event(rid, "IPV4", "10.1.2.3", "203.0.113.1")
    audit.log_event(rid, "EMAIL", "a@b.com", "x@example.pentest")
    audit.log_response(rid, 200, 2048, 2)

    s = audit.stats()
    assert s["engagement_id"] == "pytest-suite"
    assert s["requests_logged"] >= 1
    assert s["events_logged"] >= 2
    assert s["events_by_type"].get("IPV4", 0) >= 1
    assert s["events_by_type"].get("EMAIL", 0) >= 1


def test_export_csv_has_header_and_rows():
    rid = audit.new_request_id()
    audit.log_request(rid, "POST", "/v1/messages", 100)
    audit.log_event(rid, "IPV4", "10.1.2.3", "203.0.113.1")
    audit.log_response(rid, 200, 200, 1)

    csv = audit.export_csv()
    lines = csv.splitlines()

    # Header present and well-formed.
    assert lines[0].startswith("ts,request_id,engagement_id,method,path")
    assert "real_hash" in lines[0]

    body = "\n".join(lines[1:])
    assert rid in body
    assert "IPV4" in body
    assert "203.0.113.1" in body


def test_export_csv_never_contains_plaintext_real_values():
    """The whole point of the audit log: real values must not leak."""
    rid = audit.new_request_id()
    secret_real = "supersecret-unique-marker-10.1.2.3"
    audit.log_request(rid, "POST", "/v1/messages", 100)
    audit.log_event(rid, "IPV4", secret_real, "203.0.113.99")
    audit.log_response(rid, 200, 200, 1)

    csv = audit.export_csv()
    assert secret_real not in csv
    # But the hash IS present (for reconciliation).
    assert audit.hash_real(secret_real) in csv


def test_new_request_id_is_unique():
    ids = {audit.new_request_id() for _ in range(25)}
    assert len(ids) == 25
