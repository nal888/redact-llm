"""Anthropic /v1/messages adapter.

Responsibilities:
  - Walk request body, anonymize user-authored text
  - Recompute `cc_version` fingerprint to match modified first user message
  - Strip `cch=...;` native attestation (we cannot recompute it)
  - Parse SSE response, deanonymize text_delta + input_json_delta per content block
"""
import hashlib
import json
import logging
import re
from typing import AsyncIterator

from ..anonymizer import anonymize_text, deanonymize_text

log = logging.getLogger("anon-proxy.anthropic")

# From Claude Code source: src/utils/fingerprint.ts
FINGERPRINT_SALT = "59cf53e54c78"
FINGERPRINT_INDICES = (4, 7, 20)

_BILLING_HEADER_RE = re.compile(
    r"(x-anthropic-billing-header:\s*cc_version=)(?P<ver>[\d.]+)\.(?P<fp>[0-9a-f]{3})"
)
_CCH_RE = re.compile(r"\s*cch=[0-9a-f]+;")


def _compute_fingerprint(first_user_text: str, version: str) -> str:
    chars = "".join(first_user_text[i] if i < len(first_user_text) else "0"
                    for i in FINGERPRINT_INDICES)
    h = hashlib.sha256(f"{FINGERPRINT_SALT}{chars}{version}".encode()).hexdigest()
    return h[:3]


def _first_user_text(messages: list) -> str:
    for m in messages:
        if m.get("role") != "user":
            continue
        content = m.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for block in content:
                if block.get("type") == "text":
                    return block.get("text", "")
    return ""


def _fix_billing_block(system_block: dict, new_fingerprint: str) -> None:
    """Update cc_version fingerprint + strip cch= from the billing text block."""
    text = system_block.get("text", "")
    if "x-anthropic-billing-header" not in text:
        return
    # Update fingerprint
    def _sub(m):
        return f"{m.group(1)}{m.group('ver')}.{new_fingerprint}"
    text = _BILLING_HEADER_RE.sub(_sub, text)
    # Strip cch= entirely (we can't recompute Bun native attestation)
    text = _CCH_RE.sub("", text)
    system_block["text"] = text


def anonymize_request(body_bytes: bytes) -> bytes:
    try:
        body = json.loads(body_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body_bytes  # not JSON — pass through unchanged

    def _anon_any(x, use_llm=True):
        if isinstance(x, str):
            return anonymize_text(x, use_llm=use_llm)
        if isinstance(x, list):
            return [_anon_any(v, use_llm) for v in x]
        if isinstance(x, dict):
            return {k: _anon_any(v, use_llm) for k, v in x.items()}
        return x

    # Anonymize messages[*].content[*] — LLM-enabled, this is user-authored
    for msg in body.get("messages", []):
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = anonymize_text(content, use_llm=True)
        elif isinstance(content, list):
            for block in content:
                btype = block.get("type")
                if btype == "text" and "text" in block:
                    block["text"] = anonymize_text(block["text"], use_llm=True)
                elif btype == "tool_use" and "input" in block:
                    block["input"] = _anon_any(block["input"], use_llm=True)
                elif btype == "tool_result":
                    tc = block.get("content")
                    if isinstance(tc, str):
                        block["content"] = anonymize_text(tc, use_llm=True)
                    elif isinstance(tc, list):
                        for sub in tc:
                            if sub.get("type") == "text" and "text" in sub:
                                sub["text"] = anonymize_text(sub["text"], use_llm=True)

    # Anonymize system[*].text — regex only (system prompts are Claude Code's, not client data).
    # Skip the billing block (fixed separately below).
    system = body.get("system")
    if isinstance(system, list):
        for block in system:
            if block.get("type") != "text":
                continue
            text = block.get("text", "")
            if "x-anthropic-billing-header" in text:
                continue
            block["text"] = anonymize_text(text, use_llm=False)
    elif isinstance(system, str):
        body["system"] = anonymize_text(system)

    # Recompute fingerprint from the (now anonymized) first user message
    new_ft = _first_user_text(body.get("messages", []))
    new_fp = _compute_fingerprint(new_ft, version="")  # version baked into text already
    # But the real formula uses MACRO.VERSION. We extract it from the billing block
    # if present, and recompute properly.
    if isinstance(system, list):
        for block in system:
            if block.get("type") == "text" and "x-anthropic-billing-header" in block.get("text", ""):
                ver_match = _BILLING_HEADER_RE.search(block["text"])
                if ver_match:
                    version = ver_match.group("ver")
                    new_fp = _compute_fingerprint(new_ft, version)
                _fix_billing_block(block, new_fp)

    return json.dumps(body, ensure_ascii=False).encode()


# ---------- SSE response handling ----------

async def _sse_frames(raw: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Split upstream bytes into SSE frames (terminated by blank line)."""
    buf = b""
    async for chunk in raw:
        buf += chunk
        while b"\n\n" in buf:
            frame, buf = buf.split(b"\n\n", 1)
            yield frame
    if buf:
        yield buf


def _parse_frame(frame: bytes) -> tuple[str | None, dict | None, bytes]:
    """Extract event name and JSON data from an SSE frame."""
    lines = frame.split(b"\n")
    event = None
    data_line = None
    for ln in lines:
        if ln.startswith(b"event: "):
            event = ln[7:].decode().strip()
        elif ln.startswith(b"data: "):
            data_line = ln[6:]
    data = None
    if data_line is not None:
        try:
            data = json.loads(data_line)
        except json.JSONDecodeError:
            data = None
    return event, data, frame


def _emit_frame(event: str, data: dict) -> bytes:
    payload = json.dumps(data, ensure_ascii=False).encode()
    return f"event: {event}\ndata: ".encode() + payload + b"\n\n"


async def deanonymize_stream(raw: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    """Buffer text + tool-use JSON per content_block_index, deanonymize at block_stop."""
    text_bufs: dict[int, list[str]] = {}
    json_bufs: dict[int, list[str]] = {}
    frame_count = 0
    events_seen: dict[str, int] = {}

    async for frame in _sse_frames(raw):
        frame_count += 1
        event, data, raw_frame = _parse_frame(frame)
        events_seen[event or "<none>"] = events_seen.get(event or "<none>", 0) + 1

        if event == "content_block_delta" and data is not None:
            idx = data.get("index", 0)
            delta = data.get("delta", {})
            dtype = delta.get("type")
            if dtype == "text_delta":
                text_bufs.setdefault(idx, []).append(delta.get("text", ""))
                continue  # suppress; emit deanonymized at block_stop
            if dtype == "input_json_delta":
                json_bufs.setdefault(idx, []).append(delta.get("partial_json", ""))
                continue
            # thinking_delta / signature_delta / other — pass through untouched
            yield raw_frame + b"\n\n"
            continue

        if event == "content_block_stop" and data is not None:
            idx = data.get("index", 0)
            if idx in text_bufs:
                full = "".join(text_bufs.pop(idx))
                deanon = deanonymize_text(full)
                if full != deanon:
                    log.info(f"deanon text block {idx}: {len(full)}ch, changed")
                yield _emit_frame("content_block_delta", {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "text_delta", "text": deanon},
                })
            if idx in json_bufs:
                full = "".join(json_bufs.pop(idx))
                deanon = deanonymize_text(full)
                if full != deanon:
                    log.info(f"deanon tool_use block {idx}: {len(full)}ch, changed")
                yield _emit_frame("content_block_delta", {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "input_json_delta", "partial_json": deanon},
                })
            yield raw_frame + b"\n\n"
            continue

        # pass through all other events as-is
        yield raw_frame + b"\n\n"
