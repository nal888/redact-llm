"""Tests for anon_proxy.anonymizer — end-to-end anonymize/deanonymize."""
from __future__ import annotations

from anon_proxy import anonymizer, detector


# ---------------------------------------------------------------------------
# Round-trip: anonymize -> deanonymize restores the original.
# ---------------------------------------------------------------------------

def test_roundtrip_simple_ipv4():
    # Surround IPs with spaces; the IPv4 regex's trailing negative lookahead
    # intentionally refuses to match when an IP is immediately followed by a
    # dot (to avoid capturing the leading octets of a larger numeric token),
    # so we avoid putting an IP flush at end-of-sentence.
    src = "Attacker pivoted from 10.1.2.3 to 10.1.2.4 then exfiltrated."
    anon = anonymizer.anonymize_text(src)
    assert "10.1.2.3" not in anon
    assert "10.1.2.4" not in anon
    assert anonymizer.deanonymize_text(anon) == src


def test_roundtrip_mixed_entities():
    src = (
        "User CONTOSO\\jsmith on dc01-prod (10.1.2.3) accessed "
        "alice@acme.com and pulled hash "
        "aad3b435b51404eeaad3b435b51404ee from corp.acme.com."
    )
    anon = anonymizer.anonymize_text(src)
    # None of the sensitive tokens survive.
    for sensitive in [
        "CONTOSO\\jsmith",
        "dc01-prod",
        "10.1.2.3",
        "alice@acme.com",
        "aad3b435b51404eeaad3b435b51404ee",
        "corp.acme.com",
    ]:
        assert sensitive not in anon, f"{sensitive!r} leaked into {anon!r}"

    # Deanonymize restores verbatim.
    assert anonymizer.deanonymize_text(anon) == src


def test_anonymize_is_deterministic_within_engagement():
    """Same real value → same surrogate across calls (prompt caching)."""
    a = anonymizer.anonymize_text("See 10.1.2.3 now")
    b = anonymizer.anonymize_text("See 10.1.2.3 later")
    # Extract whatever 10.1.2.3 was replaced with.
    a_sur = a.split("See ", 1)[1].split(" ", 1)[0]
    b_sur = b.split("See ", 1)[1].split(" ", 1)[0]
    assert a_sur == b_sur


def test_anonymize_empty_input():
    assert anonymizer.anonymize_text("") == ""
    assert anonymizer.anonymize_text(None) is None


def test_deanonymize_empty_input():
    assert anonymizer.deanonymize_text("") == ""
    assert anonymizer.deanonymize_text(None) is None


def test_text_with_no_entities_unchanged():
    src = "This is a plain sentence with no sensitive data."
    assert anonymizer.anonymize_text(src) == src
    assert anonymizer.deanonymize_text(src) == src


# ---------------------------------------------------------------------------
# False-positive resistance
# ---------------------------------------------------------------------------

def test_filenames_not_anonymized():
    """Common config/source filenames must pass through untouched."""
    src = "Edit settings.json and README.md before committing app.py."
    anon = anonymizer.anonymize_text(src)
    assert "settings.json" in anon
    assert "README.md" in anon
    assert "app.py" in anon


def test_surrogate_output_not_rematched():
    """Running anonymize twice must be a no-op on the second pass.

    The surrogate IP range (203.0.113.0/24) and surrogate domain suffix
    (.pentest.local) are excluded from detection, so re-running anonymize
    on the output leaves it alone.
    """
    src = "Attack from 10.1.2.3 via corp.acme.com."
    once = anonymizer.anonymize_text(src)
    twice = anonymizer.anonymize_text(once)
    assert once == twice


def test_loopback_not_anonymized():
    src = "Listener on 127.0.0.1 ready."
    assert anonymizer.anonymize_text(src) == src


# ---------------------------------------------------------------------------
# Integration with detector
# ---------------------------------------------------------------------------

def test_all_detector_matches_are_replaced():
    src = "10.1.2.3 and dc01-prod, see alice@acme.com."
    matches = detector.detect(src)
    anon = anonymizer.anonymize_text(src)
    for m in matches:
        assert m.value not in anon, f"{m.value!r} not replaced"
