"""LLM-based entity detector (Ollama). Catches what regex can't:
bare hostnames (DC01), person names, org names, project codenames, cleartext passwords.

Design:
  - Regex-first short-circuit: skip LLM when regex already covered ≥ threshold of text
  - Chunk cache: memoize LLM results by sha256(text) → reuses across turns
  - Circuit breaker: after N consecutive timeouts, fail-open to regex-only for a cooldown
  - Hard timeout per call: prevents hanging the proxy

Opt-in via env: LLM_DETECTOR=true (default: true).
Safe to disable: LLM_DETECTOR=false — falls back to pure regex.
"""
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .detector import Match

log = logging.getLogger("anon-proxy.llm")

ENABLED = os.environ.get("LLM_DETECTOR", "true").lower() == "true"
MODEL = os.environ.get("LLM_MODEL", "llama3.2:latest")
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "15"))
MIN_TEXT_LEN = int(os.environ.get("LLM_MIN_LEN", "20"))   # skip tiny chunks
MAX_TEXT_LEN = int(os.environ.get("LLM_MAX_LEN", "4000")) # truncate huge ones
REGEX_COVERAGE_SKIP = float(os.environ.get("LLM_REGEX_SKIP", "0.25"))  # if regex already covers >= this fraction, skip LLM

# Circuit breaker state (module-global; simple, good enough).
_cb_lock = threading.Lock()
_cb = {"failures": 0, "opened_at": 0.0}
_CB_THRESHOLD = 3
_CB_COOLDOWN = 60.0  # seconds

# In-memory cache: sha256(text) → list[Match].
_cache_lock = threading.Lock()
_cache: dict[str, list[Match]] = {}
_CACHE_MAX = 512


# ---------- Prompt + schema ----------

_SYSTEM = """You are a cybersecurity-pentest data classifier. Extract named entities from the given text.

ONLY output entities of these types:
- HOSTNAME: bare Windows/Linux machine names like "DC01", "WEB-PROD-02", "fileserver", "kali-lab". NOT tool names.
- PERSON: real human names like "John Smith", "Alice", "M. Rodriguez". NOT usernames/handles alone.
- ORG: company or organization names like "Acme Corp", "Contoso Ltd", "ACME Bank".
- CODENAME: project or operation codenames like "Operation Phoenix", "Project Blackbird".
- PASSWORD: a string stated in context as a password/credential, e.g. "password: Summer2024!" -> "Summer2024!".

NEVER output as entities: tool names (nmap, hashcat, burp, metasploit, nuclei, crackmapexec),
protocols (SMB, NTLM, LDAP, RDP, HTTP, TLS, Kerberos, DNS, TCP, UDP), product names (Windows, Linux, Kali,
macOS, Active Directory as a concept), common words, code identifiers, file names, URLs, IPs, emails,
hashes, tokens. Those are handled separately.

If none found, return {"entities":[]}.

Output strict JSON matching the schema. No commentary."""

_SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "type": {"type": "string", "enum": ["HOSTNAME", "PERSON", "ORG", "CODENAME", "PASSWORD"]},
                },
                "required": ["text", "type"],
            },
        }
    },
    "required": ["entities"],
}

_FEW_SHOT = [
    {"role": "user", "content": 'ran nmap -sV on DC01 and FILESERVER-02, user was john.smith'},
    {"role": "assistant", "content": '{"entities":[{"text":"DC01","type":"HOSTNAME"},{"text":"FILESERVER-02","type":"HOSTNAME"},{"text":"john.smith","type":"PERSON"}]}'},
    {"role": "user", "content": 'SMB relay via NTLM against Acme Corporation as part of Operation Blackwing'},
    {"role": "assistant", "content": '{"entities":[{"text":"Acme Corporation","type":"ORG"},{"text":"Operation Blackwing","type":"CODENAME"}]}'},
    {"role": "user", "content": 'the admin password is Summer2024! and the backup password is Winter2023@'},
    {"role": "assistant", "content": '{"entities":[{"text":"Summer2024!","type":"PASSWORD"},{"text":"Winter2023@","type":"PASSWORD"}]}'},
]


# ---------- Circuit breaker ----------

def _cb_open() -> bool:
    with _cb_lock:
        if _cb["failures"] < _CB_THRESHOLD:
            return False
        if time.time() - _cb["opened_at"] > _CB_COOLDOWN:
            _cb["failures"] = 0
            return False
        return True


def _cb_record_failure():
    with _cb_lock:
        _cb["failures"] += 1
        if _cb["failures"] >= _CB_THRESHOLD:
            _cb["opened_at"] = time.time()
            log.warning(f"LLM circuit breaker opened after {_CB_THRESHOLD} failures — cooldown {_CB_COOLDOWN}s")


def _cb_record_success():
    with _cb_lock:
        _cb["failures"] = 0


# ---------- Coverage check ----------

def _regex_coverage(text_len: int, regex_matches: list[Match]) -> float:
    if text_len == 0:
        return 0.0
    covered = sum(m.end - m.start for m in regex_matches)
    return covered / text_len


# ---------- Cache ----------

def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _cache_get(key: str) -> list[Match] | None:
    with _cache_lock:
        return _cache.get(key)


def _cache_put(key: str, matches: list[Match]):
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            # drop oldest half
            for k in list(_cache.keys())[: _CACHE_MAX // 2]:
                _cache.pop(k, None)
        _cache[key] = matches


# ---------- Ollama call ----------

def _call_ollama(text: str) -> list[dict[str, str]]:
    messages = [{"role": "system", "content": _SYSTEM}, *_FEW_SHOT,
                {"role": "user", "content": text}]
    body = {
        "model": MODEL,
        "messages": messages,
        "format": _SCHEMA,
        "stream": False,
        "options": {"temperature": 0, "num_ctx": 4096},
    }
    with httpx.Client(timeout=TIMEOUT) as client:
        r = client.post(f"{OLLAMA_HOST}/api/chat", json=body)
    r.raise_for_status()
    raw = r.json()["message"]["content"]
    try:
        parsed = json.loads(raw)
        return parsed.get("entities", [])
    except json.JSONDecodeError:
        log.debug(f"LLM returned non-JSON: {raw[:200]}")
        return []


def _entities_to_matches(entities: list[dict], text: str) -> list[Match]:
    out: list[Match] = []
    for ent in entities:
        val = ent.get("text", "").strip()
        typ = ent.get("type", "").strip().upper()
        if not val or typ not in ("HOSTNAME", "PERSON", "ORG", "CODENAME", "PASSWORD"):
            continue
        # Find first occurrence in text
        idx = text.find(val)
        if idx < 0:
            continue
        out.append(Match(typ, idx, idx + len(val), val))
    return out


# ---------- Public API ----------

def warmup() -> None:
    """Preload the model into Ollama memory so the first real request isn't cold.
    Safe to fail silently — if Ollama is down, circuit breaker handles it later.
    """
    if not ENABLED:
        return
    try:
        log.info(f"warming up LLM model: {MODEL}")
        t0 = time.time()
        _call_ollama("warmup")
        log.info(f"LLM warmup complete in {time.time() - t0:.1f}s")
    except Exception as e:
        log.warning(f"LLM warmup failed ({e.__class__.__name__}) — will retry on first real call")


def detect(text: str, regex_matches: list[Match]) -> list[Match]:
    """Run LLM-based entity extraction on text. Returns additional Match objects
    to merge with regex matches. Empty list on any failure / skip condition."""
    if not ENABLED:
        return []
    if len(text) < MIN_TEXT_LEN:
        return []
    if _cb_open():
        return []
    if _regex_coverage(len(text), regex_matches) >= REGEX_COVERAGE_SKIP:
        return []

    # Truncate oversized input
    if len(text) > MAX_TEXT_LEN:
        text = text[:MAX_TEXT_LEN]

    key = _cache_key(text)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    try:
        t0 = time.time()
        entities = _call_ollama(text)
        dt = time.time() - t0
        log.debug(f"LLM detect {len(text)}ch in {dt:.2f}s -> {len(entities)} entities")
        _cb_record_success()
    except (httpx.TimeoutException, httpx.ConnectError) as e:
        log.warning(f"LLM detector unreachable: {e.__class__.__name__} — falling back to regex only")
        _cb_record_failure()
        return []
    except Exception as e:
        log.warning(f"LLM detect failed: {e.__class__.__name__}: {e}")
        _cb_record_failure()
        return []

    matches = _entities_to_matches(entities, text)
    _cache_put(key, matches)
    return matches
