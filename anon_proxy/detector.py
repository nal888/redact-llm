"""Regex-based entity detection. Order matters: specific → generic.

Also supports an optional wordlist (known sensitive strings for the current
engagement) that is matched before regex — see `load_wordlist()`.
"""
import logging
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("anon-proxy.detector")

# Populated by load_wordlist(); list of (entity_type, value, compiled_pattern).
# Matching is case-insensitive and word-boundary-anchored (`\b...\b`).
# Longer values are tried first (greedy).
_WORDLIST: list[tuple[str, str, re.Pattern]] = []


def load_wordlist(path: str | Path) -> int:
    """Load a newline-separated list of known sensitive values.

    Each line is either:
        value
        value:TYPE

    Lines starting with `#` and blank lines are skipped. Returns count loaded.
    Longer values are tried first (greedy match).
    """
    _WORDLIST.clear()
    p = Path(path)
    if not p.exists():
        log.warning(f"wordlist file not found: {path}")
        return 0
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                value, _, type_ = line.rpartition(":")
                value = value.strip()
                type_ = type_.strip().upper() or "CUSTOM"
            else:
                value, type_ = line, "CUSTOM"
            if value:
                pat = re.compile(r"\b" + re.escape(value) + r"\b", re.IGNORECASE)
                _WORDLIST.append((type_, value, pat))
    _WORDLIST.sort(key=lambda x: -len(x[1]))
    log.info(f"loaded {len(_WORDLIST)} wordlist entries from {path}")
    return len(_WORDLIST)

# Never anonymize these — common tool names, protocols, ports, RFC docs, etc.
NEVER_ANONYMIZE = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "localhost", "example.com", "example.org", "example.net",
    "pentest.local", "test.local",
}

# IP prefixes we reserve for our own surrogates — never treat as "real" data.
SURROGATE_IPV4_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.")

# Domain suffixes our surrogates use — never re-anonymize.
SURROGATE_DOMAIN_SUFFIXES = (".pentest.local", ".example.pentest", "pentest.local", "example.pentest")

# File extensions that should never be treated as domain TLDs.
_FILE_EXTS = {
    "json", "md", "txt", "yaml", "yml", "toml", "ini", "cfg", "conf", "env",
    "py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "rb", "pl", "php", "go",
    "rs", "c", "cpp", "h", "hpp", "hh", "cc", "java", "kt", "swift",
    "sh", "bash", "zsh", "ps1", "bat", "cmd",
    "html", "htm", "xml", "xsd", "css", "scss", "sass", "less",
    "log", "lock", "bak", "tmp", "swp", "orig",
    "pdf", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
    "zip", "tar", "gz", "bz2", "7z", "rar", "xz", "zst",
    "mp3", "mp4", "wav", "mov", "avi", "mkv", "webm",
    "csv", "tsv", "xls", "xlsx", "doc", "docx", "ppt", "pptx", "odt",
    "jar", "war", "ear", "exe", "dll", "so", "dylib", "o", "a", "bin",
    "db", "sqlite", "sqlite3",
    "map", "min", "d", "mod", "sum",
    "dockerfile", "gitignore", "gitattributes", "gitkeep",
    "example", "sample", "template", "dist",
}


def _looks_like_file(value: str) -> bool:
    """Heuristic: last dotted segment is a known file extension."""
    last = value.rsplit(".", 1)[-1].lower()
    return last in _FILE_EXTS


@dataclass(frozen=True)
class Match:
    entity_type: str
    start: int
    end: int
    value: str


_IPV4 = r"(?<![\w\.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![\w\.])"
_IPV4_CIDR = _IPV4 + r"/\d{1,2}"
_IPV6 = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b"
_MAC = r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"
_EMAIL = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
_URL = r"\bhttps?://[a-zA-Z0-9][a-zA-Z0-9._-]*(?:\.[a-zA-Z]{2,})+(?::\d+)?(?:/[^\s]*)?"
_DOMAIN = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+(?:local|corp|internal|lan|intra|[a-zA-Z]{2,})\b"
_MD5 = r"\b[a-fA-F0-9]{32}\b"
_SHA1 = r"\b[a-fA-F0-9]{40}\b"
_SHA256 = r"\b[a-fA-F0-9]{64}\b"
_AWS_ACCESS_KEY = r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
_JWT = r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"

# Phase A+ additions —
_AD_USER = r"\b[A-Z][A-Z0-9-]{1,14}\\[a-zA-Z0-9._$-]+\b"              # CONTOSO\jsmith
_SID = r"\bS-1-(?:\d+-){1,14}\d+\b"                                   # S-1-5-21-...-500
_UNC = r"\\\\[a-zA-Z0-9._-]+(?:\\[^\\\s\"'<>|]+)+"                    # \\server\share\path
_SSH_PRIVKEY = r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH |EC |DSA |)PRIVATE KEY-----"
_API_TOKEN = r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[bpaors]-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{35})"
_BEARER = r"(?<=Bearer )\b[A-Za-z0-9._\-]{20,}\b"
_UUID = r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
_ARN = r"\barn:aws[a-zA-Z-]*:[a-zA-Z0-9-]*:[a-zA-Z0-9-]*:\d{0,12}:[a-zA-Z0-9./:_-]+"
_AWS_ACCOUNT = r"(?<!\d)\d{12}(?!\d)"                                 # standalone 12-digit number; false-positive risk
_LDAP_DN = r"(?:CN|OU|DC)=[^,\s]+(?:,\s?(?:CN|OU|DC)=[^,\s]+){1,}"    # CN=Admin,DC=acme,DC=corp
_CREDIT_CARD = r"\b(?:\d[ -]?){13,19}\b"
_PHONE_E164 = r"\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{2,4}[\s-]?\d{2,4}(?:[\s-]?\d{2,4})?"
_HOSTNAME_FORMAL = r"\b(?:dc|srv|fs|ws|exch|sql|web|app|dev|prod|stg|test|mail|vpn|ftp|ad|dns|db)\d{1,4}(?:-[a-zA-Z0-9]+)?\b"
# ORG fallback: 1-3 capitalized words followed by corporate suffix.
# Catches "Acme Corp", "Contoso Corporation", "Globex Inc", "Foo Bar Ltd" etc.
_ORG = r"\b(?:[A-Z][a-zA-Z0-9&-]{1,20}\s+){1,3}(?:Corp(?:oration)?|Inc(?:orporated)?|Ltd|LLC|GmbH|AG|SA|SAS|BV|Pty|PLC|AB|Co|Holdings|Group|Technologies|Labs|Systems|Solutions|Partners)\b"

# Priority: longer/more-specific first
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SSH_PRIVKEY", re.compile(_SSH_PRIVKEY, re.MULTILINE)),
    ("IPV4_CIDR", re.compile(_IPV4_CIDR)),
    ("URL", re.compile(_URL)),
    ("EMAIL", re.compile(_EMAIL)),
    ("JWT", re.compile(_JWT)),
    ("API_TOKEN", re.compile(_API_TOKEN)),
    ("BEARER_TOKEN", re.compile(_BEARER)),
    ("AWS_ACCESS_KEY", re.compile(_AWS_ACCESS_KEY)),
    ("ARN", re.compile(_ARN)),
    ("LDAP_DN", re.compile(_LDAP_DN)),
    ("UNC_PATH", re.compile(_UNC)),
    ("AD_USER", re.compile(_AD_USER)),
    ("SID", re.compile(_SID)),
    ("UUID", re.compile(_UUID)),
    ("SHA256", re.compile(_SHA256)),
    ("SHA1", re.compile(_SHA1)),
    ("MD5", re.compile(_MD5)),            # also matches NTLM
    ("IPV6", re.compile(_IPV6)),
    ("IPV4", re.compile(_IPV4)),
    ("MAC", re.compile(_MAC)),
    ("DOMAIN", re.compile(_DOMAIN)),
    ("HOSTNAME", re.compile(_HOSTNAME_FORMAL, re.IGNORECASE)),
    ("ORG", re.compile(_ORG)),
    ("CREDIT_CARD", re.compile(_CREDIT_CARD)),
    ("PHONE", re.compile(_PHONE_E164)),
    # AWS_ACCOUNT last — 12-digit bare number is noisy; keep behind other specific patterns
    ("AWS_ACCOUNT", re.compile(_AWS_ACCOUNT)),
]


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"[\s-]", "", number) if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect(text: str) -> list[Match]:
    """Return non-overlapping matches.

    Ordering:
      1. Regex patterns run first, so composite entities (e.g. `CONTOSO\\user`
         matched as AD_USER) win over their substring components.
      2. Wordlist (operator-supplied known values) runs second, filling in
         standalone mentions regex didn't cover.

    Wordlist matches are case-insensitive and word-boundary-anchored
    (`\\bvalue\\b`), so `jsmith` in the wordlist won't match inside
    `jsmithson@example.com`.
    """
    hits: list[Match] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        return any(not (b <= s or a >= e) for s, e in claimed)

    for entity_type, pat in _PATTERNS:
        for m in pat.finditer(text):
            s, e = m.start(), m.end()
            if overlaps(s, e):
                continue
            val = m.group(0)
            if val in NEVER_ANONYMIZE:
                continue
            if entity_type in ("IPV4", "IPV4_CIDR") and val.startswith(SURROGATE_IPV4_PREFIXES):
                continue
            if entity_type == "DOMAIN":
                if _looks_like_file(val):
                    continue
                if val.endswith(SURROGATE_DOMAIN_SUFFIXES):
                    continue
            if entity_type == "CREDIT_CARD" and not _luhn_valid(val):
                continue
            if entity_type == "AWS_ACCOUNT":
                # very noisy — only flag if context suggests AWS (this is weak; ARN matches supersede)
                # Skip in v1 unless we see it in an AWS-like context — disable by default.
                continue
            hits.append(Match(entity_type, s, e, val))
            claimed.append((s, e))

    # Wordlist second — fills in values regex didn't already cover.
    # Case-insensitive, word-boundary-anchored. The matched surface text
    # (in its original case) becomes the key, so "ACME" and "acme" map
    # to separate vault entries — use the wordlist as your canonical list
    # of variants you want covered.
    for entity_type, _value, pat in _WORDLIST:
        for m in pat.finditer(text):
            s, e = m.start(), m.end()
            if overlaps(s, e):
                continue
            surface = text[s:e]
            hits.append(Match(entity_type, s, e, surface))
            claimed.append((s, e))

    hits.sort(key=lambda h: h.start)
    return hits
