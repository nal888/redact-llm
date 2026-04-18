"""Tests for anon_proxy.detector — entity detection contract."""
from __future__ import annotations

import pytest

from anon_proxy import detector


def _types(text: str) -> set[str]:
    return {m.entity_type for m in detector.detect(text)}


def _values(text: str, entity_type: str) -> list[str]:
    return [m.value for m in detector.detect(text) if m.entity_type == entity_type]


# ---------------------------------------------------------------------------
# Positive cases — each entity type must be detected at least once.
# ---------------------------------------------------------------------------

def test_detects_ipv4():
    assert "IPV4" in _types("The target is 10.1.2.3 on the LAN.")


def test_detects_ipv4_cidr():
    assert "IPV4_CIDR" in _types("Scope: 10.1.2.0/24 is in range.")


def test_detects_domain():
    assert "DOMAIN" in _types("Resolve corp.acme.com for me.")


def test_detects_email():
    assert "EMAIL" in _types("Contact jsmith@acme.com for access.")


def test_detects_md5():
    # 32 hex chars, real-looking NTLM hash
    assert "MD5" in _types("NT hash: aad3b435b51404eeaad3b435b51404ee now cracked")


def test_detects_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert "SHA256" in _types(f"sha256: {h}")


def test_detects_ad_user():
    assert "AD_USER" in _types("Login CONTOSO\\jsmith succeeded.")


def test_detects_sid():
    assert "SID" in _types("Domain admin SID is S-1-5-21-1111-2222-3333-500.")


def test_detects_arn():
    arn = "arn:aws:iam::123456789012:user/alice"
    assert "ARN" in _types(f"Role: {arn}")


def test_detects_jwt():
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0nG4GH2vE5n3CvHhM"
    )
    assert "JWT" in _types(f"Token {jwt} from intercepted request")


def test_detects_uuid():
    assert "UUID" in _types("Session id: 550e8400-e29b-41d4-a716-446655440000 captured.")


def test_detects_phone():
    assert "PHONE" in _types("Call the SOC on +1-555-867-5309 after hours.")


def test_detects_credit_card_luhn_valid():
    # Known valid Visa test number (passes Luhn).
    assert "CREDIT_CARD" in _types("Card 4111 1111 1111 1111 on file.")


def test_detects_url():
    assert "URL" in _types("Docs at https://wiki.acme.com/runbook now.")


def test_detects_api_token_github():
    assert "API_TOKEN" in _types("export GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789")


def test_detects_bearer_token():
    assert "BEARER_TOKEN" in _types("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123")


def test_detects_ldap_dn():
    assert "LDAP_DN" in _types("DN CN=Admin,OU=IT,DC=acme,DC=corp is privileged.")


def test_detects_unc_path():
    assert "UNC_PATH" in _types("File at \\\\fileserver\\shared\\secrets.txt leaked.")


def test_detects_ssh_privkey():
    blob = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAA\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    assert "SSH_PRIVKEY" in _types(f"Found key:\n{blob}\nin backup")


def test_detects_hostname():
    assert "HOSTNAME" in _types("Box dc01-prod is the PDC emulator.")


# ---------------------------------------------------------------------------
# Negative cases — false positives we must not flag.
# ---------------------------------------------------------------------------

def test_settings_json_not_domain():
    """`settings.json` is a filename, not a TLD."""
    assert "DOMAIN" not in _types("Edit settings.json before deploy.")


@pytest.mark.parametrize(
    "fname",
    ["README.md", "config.yaml", "app.py", "package.json", "main.go"],
)
def test_common_filenames_not_domains(fname):
    assert "DOMAIN" not in _types(f"Open {fname} to see the config.")


def test_invalid_credit_card_rejected_by_luhn():
    # Right length/shape, wrong checksum → not flagged.
    assert "CREDIT_CARD" not in _types("Fake card 1234 5678 9012 3456 for sure.")


def test_surrogate_ipv4_range_not_rematched():
    """Anything in 203.0.113.0/24 is our own surrogate space — never rematch."""
    assert "IPV4" not in _types("Surrogate 203.0.113.42 emitted by proxy.")


def test_localhost_never_anonymized():
    assert detector.detect("connect to 127.0.0.1 please") == []


def test_example_com_never_anonymized():
    assert "DOMAIN" not in _types("See example.com for details.")


def test_surrogate_domain_suffix_not_rematched():
    assert "DOMAIN" not in _types("Surrogate abc123.pentest.local used.")


# ---------------------------------------------------------------------------
# Overlap / ordering contract.
# ---------------------------------------------------------------------------

def test_matches_are_non_overlapping_and_sorted():
    text = "Host dc01-prod at 10.1.2.3 user CONTOSO\\alice mailto alice@acme.com"
    matches = detector.detect(text)
    # Sorted
    assert matches == sorted(matches, key=lambda m: m.start)
    # Non-overlapping
    for a, b in zip(matches, matches[1:]):
        assert a.end <= b.start


def test_email_wins_over_domain_on_overlap():
    """EMAIL is higher priority than DOMAIN and should claim the span."""
    matches = detector.detect("send to alice@acme.com now")
    types = [m.entity_type for m in matches]
    assert "EMAIL" in types
    assert "DOMAIN" not in types  # acme.com inside the email can't double-match


def test_empty_input():
    assert detector.detect("") == []
    assert detector.detect("no entities in this plain english sentence") == []
