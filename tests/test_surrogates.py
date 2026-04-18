"""Tests for anon_proxy.surrogates — determinism and format preservation."""
from __future__ import annotations

import hmac
import hashlib
import ipaddress
import re
import uuid as _uuid

import pytest

from anon_proxy import config, surrogates, vault


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "entity_type,real",
    [
        ("IPV4", "10.1.2.3"),
        ("DOMAIN", "corp.acme.com"),
        ("EMAIL", "alice@acme.com"),
        ("MD5", "aad3b435b51404eeaad3b435b51404ee"),
        ("UUID", "550e8400-e29b-41d4-a716-446655440000"),
    ],
)
def test_surrogate_is_deterministic(entity_type, real):
    a = surrogates.surrogate(entity_type, real)
    b = surrogates.surrogate(entity_type, real)
    assert a == b


def test_different_reals_yield_different_surrogates():
    a = surrogates.surrogate("IPV4", "10.1.2.3")
    b = surrogates.surrogate("IPV4", "10.1.2.4")
    assert a != b


def test_different_engagement_secret_yields_different_surrogate(monkeypatch):
    """Same (type, real) but different secret → different surrogate.

    We patch ENGAGEMENT_SECRET on the config module (surrogates reads it by
    reference each call via ``config.ENGAGEMENT_SECRET``).
    """
    original = config.ENGAGEMENT_SECRET
    real = "10.99.99.99"

    # Need to clear the vault or the cached mapping short-circuits _ipv4.
    vault.clear()
    monkeypatch.setattr(config, "ENGAGEMENT_SECRET", b"A" * 32)
    sur_a = surrogates.surrogate("IPV4", real)

    vault.clear()
    monkeypatch.setattr(config, "ENGAGEMENT_SECRET", b"B" * 32)
    sur_b = surrogates.surrogate("IPV4", real)

    # restore
    monkeypatch.setattr(config, "ENGAGEMENT_SECRET", original)
    assert sur_a != sur_b


# ---------------------------------------------------------------------------
# Format preservation — surrogates must still look like the entity type.
# ---------------------------------------------------------------------------

def test_ipv4_surrogate_is_valid_ipv4_in_testnet3():
    sur = surrogates.surrogate("IPV4", "10.1.2.3")
    # Must parse as IPv4 and fall in 203.0.113.0/24 (RFC 5737 TEST-NET-3).
    ip = ipaddress.IPv4Address(sur)
    assert ip in ipaddress.IPv4Network("203.0.113.0/24")


def test_ipv4_cidr_surrogate_preserves_prefix_length():
    sur = surrogates.surrogate("IPV4_CIDR", "10.1.2.0/24")
    net = ipaddress.IPv4Network(sur, strict=False)
    assert net.prefixlen == 24


def test_uuid_surrogate_has_valid_uuid_shape():
    sur = surrogates.surrogate("UUID", "550e8400-e29b-41d4-a716-446655440000")
    # Must parse as a UUID.
    _uuid.UUID(sur)


def test_md5_surrogate_is_32_hex():
    sur = surrogates.surrogate("MD5", "aad3b435b51404eeaad3b435b51404ee")
    assert re.fullmatch(r"[0-9a-f]{32}", sur)


def test_sha256_surrogate_is_64_hex():
    real = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sur = surrogates.surrogate("SHA256", real)
    assert re.fullmatch(r"[0-9a-f]{64}", sur)


def test_email_surrogate_is_well_formed():
    sur = surrogates.surrogate("EMAIL", "alice@acme.com")
    assert "@" in sur
    local, domain = sur.split("@", 1)
    assert local and domain
    # Lands on our reserved surrogate suffix.
    assert "pentest" in domain


def test_domain_surrogate_ends_in_pentest_local():
    sur = surrogates.surrogate("DOMAIN", "corp.acme.com")
    assert sur.endswith(".pentest.local")


def test_ad_user_surrogate_shape():
    sur = surrogates.surrogate("AD_USER", "CONTOSO\\jsmith")
    assert "\\" in sur and sur.startswith("PENTEST\\")


def test_sid_surrogate_shape():
    sur = surrogates.surrogate("SID", "S-1-5-21-1111-2222-3333-500")
    assert sur.startswith("S-1-5-21-")


def test_jwt_surrogate_has_three_parts():
    real = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig"
    sur = surrogates.surrogate("JWT", real)
    assert sur.count(".") == 2


def test_surrogate_is_stored_in_vault():
    surrogates.surrogate("IPV4", "10.7.7.7")
    assert vault.surrogate_for("IPV4", "10.7.7.7") is not None


def test_generic_fallback_for_unknown_type():
    sur = surrogates.surrogate("WEIRD_TYPE", "xyzzy")
    # Generic emits a [TOKEN_...] placeholder.
    assert sur.startswith("[TOKEN_") and sur.endswith("]")
