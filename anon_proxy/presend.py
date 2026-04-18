"""Pre-send safety scanner.

Runs AFTER anonymize_request has modified the body. Scans the serialized
outgoing bytes one more time with the full detector. Any high-sensitivity
match that is NOT a known surrogate (and not a known-safe value) is treated
as a potential leak: logged, counted, and optionally blocked.
"""
import logging
import os

from . import audit, detector, vault

log = logging.getLogger("anon-proxy.presend")

MODE = os.environ.get("PRESEND_MODE", "warn").lower()   # warn | block | off

# Only these types trigger presend alerts. Excluded types (UUID, SHA*, URL,
# MD5 without context, UNC, HOSTNAME) are high false-positive since the LLM
# protocol naturally contains session IDs, tool-call IDs, cache breakpoints,
# and reference URLs that are not sensitive to leak.
HIGH_SENSITIVITY_TYPES = frozenset({
    "IPV4", "IPV4_CIDR", "IPV6",
    "EMAIL", "DOMAIN",
    "AD_USER", "SID", "LDAP_DN",
    "JWT", "API_TOKEN", "BEARER_TOKEN", "AWS_ACCESS_KEY", "ARN",
    "CREDIT_CARD", "PHONE",
    "SSH_PRIVKEY", "MAC",
})

# Known-safe values we expect to see in Claude Code / Anthropic traffic.
SAFE_DOMAINS = frozenset({
    "anthropic.com", "api.anthropic.com", "claude.ai",
    "docs.claude.com", "docs.anthropic.com", "platform.claude.com",
    "console.anthropic.com", "privacy.claude.com",
    "github.com", "docs.github.com",
    "example.com", "example.org", "example.net",
    "localhost",
})

SAFE_EMAILS = frozenset({
    "noreply@anthropic.com", "support@anthropic.com",
})


def _hash_for_log(v: str) -> str:
    """Short HMAC-hashed preview so we don't log the leaked value itself."""
    return audit.hash_real(v)[:8]


def _is_known_surrogate(value: str) -> bool:
    """True if the value IS one of our previously-generated surrogates."""
    if vault.real_for(value) is not None:
        return True
    if value.endswith(detector.SURROGATE_DOMAIN_SUFFIXES):
        return True
    if value.startswith(detector.SURROGATE_IPV4_PREFIXES):
        return True
    return False


def _is_safe_value(entity_type: str, value: str) -> bool:
    """Known-safe values that the protocol normally carries."""
    if entity_type == "DOMAIN":
        lower = value.lower()
        if lower in SAFE_DOMAINS:
            return True
        # subdomains of safe domains
        for safe in SAFE_DOMAINS:
            if lower.endswith("." + safe):
                return True
    if entity_type == "EMAIL" and value.lower() in SAFE_EMAILS:
        return True
    return False


def scan(body_bytes: bytes, request_id: str | None = None) -> tuple[list[dict], bool]:
    """Scan outgoing body for any real data that slipped through anonymization.

    Returns (findings, should_block):
      - findings: list of {type, hash, offset} dicts, never includes plaintext
      - should_block: True if MODE == 'block' and findings is non-empty
    """
    if MODE == "off":
        return [], False

    try:
        text = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return [], False

    findings: list[dict] = []
    matches = detector.detect(text)
    for m in matches:
        if m.entity_type not in HIGH_SENSITIVITY_TYPES:
            continue
        if m.value in detector.NEVER_ANONYMIZE:
            continue
        if _is_known_surrogate(m.value):
            continue
        if _is_safe_value(m.entity_type, m.value):
            continue
        findings.append({
            "type": m.entity_type,
            "hash": _hash_for_log(m.value),
            "offset": m.start,
        })

    if findings:
        summary = ", ".join(f"{f['type']}:{f['hash']}" for f in findings[:10])
        more = "" if len(findings) <= 10 else f" (+{len(findings) - 10} more)"
        log.warning(
            f"[{request_id or '-'}] ⚠️  PRESEND LEAK CHECK: "
            f"{len(findings)} unexpected entities in outgoing body: {summary}{more}"
        )
        if MODE == "block":
            log.warning(f"[{request_id or '-'}] PRESEND_MODE=block — refusing request")
            return findings, True
        log.warning(
            f"[{request_id or '-'}] PRESEND_MODE=warn — sending anyway. "
            f"Set PRESEND_MODE=block to refuse."
        )

    return findings, False
