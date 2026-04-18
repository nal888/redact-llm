"""Deterministic surrogate generation — HMAC-keyed per engagement.

Same (engagement_id, entity_type, real) always yields the same surrogate,
so prompt caching survives and cross-request references stay consistent.
"""
import base64
import hmac
import hashlib
import ipaddress

from . import config, vault


def _hmac(entity_type: str, real: str) -> bytes:
    msg = f"{entity_type}\x00{real}".encode()
    return hmac.new(config.ENGAGEMENT_SECRET, msg, hashlib.sha256).digest()


def _hex(entity_type: str, real: str, n: int) -> str:
    return _hmac(entity_type, real).hex()[:n]


def _b32(entity_type: str, real: str, n: int) -> str:
    return base64.b32encode(_hmac(entity_type, real)).decode().lower().strip("=")[:n]


def surrogate(entity_type: str, real: str) -> str:
    """Generate (or retrieve) a surrogate for a given real value."""
    existing = vault.surrogate_for(entity_type, real)
    if existing is not None:
        return existing

    fn = _GENERATORS.get(entity_type, _generic)
    sur = fn(real)
    vault.upsert(entity_type, real, sur)
    return sur


def _ipv4(real: str) -> str:
    """Map into RFC 5737 TEST-NET-3 (203.0.113.0/24) deterministically."""
    h = _hmac("IPV4", real)
    octet = h[0]
    return f"203.0.113.{octet}"


def _ipv4_cidr(real: str) -> str:
    """Preserve prefix length; fake the network."""
    try:
        net = ipaddress.IPv4Network(real, strict=False)
        h = _hmac("IPV4_CIDR", real)
        return f"203.0.113.{h[0] & 0xFC}/{net.prefixlen}"
    except Exception:
        return f"203.0.113.0/{len(real)}"


def _ipv6(real: str) -> str:
    h = _hmac("IPV6", real).hex()
    return f"2001:db8:{h[0:4]}:{h[4:8]}::{h[8:12]}"


def _mac(real: str) -> str:
    h = _hmac("MAC", real).hex()
    return ":".join(h[i:i+2] for i in range(0, 12, 2))


def _email(real: str) -> str:
    local = _b32("EMAIL", real, 8)
    return f"{local}@example.pentest"


def _domain(real: str) -> str:
    label = _b32("DOMAIN", real, 8)
    return f"{label}.pentest.local"


def _url(real: str) -> str:
    label = _b32("URL", real, 10)
    return f"https://{label}.pentest.local/"


def _md5(real: str) -> str:
    return _hex("MD5", real, 32)


def _sha1(real: str) -> str:
    return _hex("SHA1", real, 40)


def _sha256(real: str) -> str:
    return _hex("SHA256", real, 64)


def _ntlm(real: str) -> str:
    return _hex("NTLM", real, 32)


def _aws_access_key(real: str) -> str:
    return "AKIA" + _b32("AWS_ACCESS_KEY", real, 16).upper()


def _jwt(real: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = _b32("JWT", real, 24)
    sig = _b32("JWT_SIG", real, 22)
    return f"{header}.{payload}.{sig}"


def _generic(real: str) -> str:
    return f"[TOKEN_{_hex('GENERIC', real, 8).upper()}]"


def _ad_user(real: str) -> str:
    return f"PENTEST\\u{_hex('AD_USER', real, 6)}"


def _sid(real: str) -> str:
    h = _hex("SID", real, 10)
    return f"S-1-5-21-{int(h[:4], 16)}-{int(h[4:8], 16)}-{int(h[8:10], 16) * 100 + 1000}"


def _unc(real: str) -> str:
    parts = real.lstrip("\\").split("\\")
    if len(parts) >= 2:
        return f"\\\\srv-{_hex('UNC_HOST', parts[0], 4)}\\{parts[1]}"
    return f"\\\\srv-{_hex('UNC_HOST', real, 4)}\\share"


def _ssh_privkey(real: str) -> str:
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END OPENSSH PRIVATE KEY-----"


def _api_token(real: str) -> str:
    prefix = real.split("_")[0] if "_" in real else real[:4]
    return f"{prefix}_" + _b32("API_TOKEN", real, 30)


def _bearer(real: str) -> str:
    return _b32("BEARER", real, 32)


def _uuid_fake(real: str) -> str:
    h = _hex("UUID", real, 32)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _arn(real: str) -> str:
    parts = real.split(":")
    if len(parts) >= 6:
        parts[4] = "000000000000"
        parts[5] = f"pentest/{_hex('ARN', real, 6)}"
        return ":".join(parts)
    return "arn:aws:iam::000000000000:user/pentest"


def _ldap_dn(real: str) -> str:
    out = []
    for p in real.split(","):
        p = p.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            out.append(f"{k}={_hex(k + 'DN', v, 6)}")
        else:
            out.append(p)
    return ",".join(out)


def _credit_card(real: str) -> str:
    return "4111-1111-1111-" + _hex("CC", real, 4)


def _phone(real: str) -> str:
    return "+1-555-" + _hex("PHONE", real, 3) + "-" + _hex("PHONE2", real, 4)


def _hostname(real: str) -> str:
    return f"host-{_hex('HOST', real, 4)}"


def _person(real: str) -> str:
    # Deterministic fake name pool, seeded from the real value
    firsts = ["Alex", "Jordan", "Sam", "Taylor", "Morgan", "Casey", "Avery", "Riley", "Parker", "Quinn"]
    lasts = ["Kim", "Park", "Nguyen", "Patel", "Lopez", "Khan", "Silva", "Tran", "Chen", "Dubois"]
    h = _hmac("PERSON", real)
    return f"{firsts[h[0] % len(firsts)]} {lasts[h[1] % len(lasts)]}"


def _org(real: str) -> str:
    return f"PentestCorp-{_hex('ORG', real, 4).upper()}"


def _codename(real: str) -> str:
    adjectives = ["Silent", "Crimson", "Azure", "Quantum", "Obsidian", "Golden", "Iron", "Hollow", "Velvet", "Paper"]
    nouns = ["Falcon", "Harbor", "Cipher", "Lantern", "Echo", "Drift", "Cascade", "Pylon", "Stratus", "Mirage"]
    h = _hmac("CODENAME", real)
    return f"Operation {adjectives[h[0] % len(adjectives)]}{nouns[h[1] % len(nouns)]}"


def _password(real: str) -> str:
    # Deterministic but unguessable; preserves approximate length class
    base = _b32("PASSWORD", real, 12)
    return f"[REDACTED_CRED_{base[:8]}]"


def _custom(real: str) -> str:
    """Surrogate for wordlist-matched values. Use _generic token form."""
    return f"[CUSTOM_{_hex('CUSTOM', real, 8).upper()}]"


_GENERATORS = {
    "CUSTOM": _custom,
    "IPV4": _ipv4,
    "IPV4_CIDR": _ipv4_cidr,
    "IPV6": _ipv6,
    "MAC": _mac,
    "EMAIL": _email,
    "DOMAIN": _domain,
    "URL": _url,
    "MD5": _md5,
    "SHA1": _sha1,
    "SHA256": _sha256,
    "NTLM": _ntlm,
    "AWS_ACCESS_KEY": _aws_access_key,
    "JWT": _jwt,
    "AD_USER": _ad_user,
    "SID": _sid,
    "UNC_PATH": _unc,
    "SSH_PRIVKEY": _ssh_privkey,
    "API_TOKEN": _api_token,
    "BEARER_TOKEN": _bearer,
    "UUID": _uuid_fake,
    "ARN": _arn,
    "LDAP_DN": _ldap_dn,
    "CREDIT_CARD": _credit_card,
    "PHONE": _phone,
    "HOSTNAME": _hostname,
    # LLM-detected types
    "PERSON": _person,
    "ORG": _org,
    "CODENAME": _codename,
    "PASSWORD": _password,
}
