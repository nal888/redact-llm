"""Text-level anonymization + deanonymization using detector + vault + optional LLM layer."""
from contextvars import ContextVar

from . import audit, detector, llm_detector, surrogates, vault
from .detector import Match

# Per-request audit context — set by the server, consumed during text walks.
current_request_id: ContextVar[str | None] = ContextVar("current_request_id", default=None)


def _merge_matches(regex_matches: list[Match], llm_matches: list[Match]) -> list[Match]:
    """Combine regex + LLM matches, drop LLM matches that overlap regex."""
    if not llm_matches:
        return regex_matches
    regex_ranges = [(m.start, m.end) for m in regex_matches]
    merged = list(regex_matches)
    for lm in llm_matches:
        overlaps = any(not (lm.end <= s or lm.start >= e) for s, e in regex_ranges)
        if not overlaps:
            merged.append(lm)
            regex_ranges.append((lm.start, lm.end))
    merged.sort(key=lambda m: m.start)
    return merged


def anonymize_text(text: str, use_llm: bool = False) -> str:
    """Anonymize text. use_llm=True enables LLM layer (expensive, CPU-bound).
    Callers should enable LLM only for user-authored content (messages,
    tool_result) — NOT system prompts or tool schemas.
    """
    if not text:
        return text
    regex_matches = detector.detect(text)
    llm_matches = llm_detector.detect(text, regex_matches) if use_llm else []
    matches = _merge_matches(regex_matches, llm_matches)
    if not matches:
        return text
    out = []
    last = 0
    req_id = current_request_id.get()
    for m in matches:
        if m.start < last:
            continue  # skip overlaps (safety net)
        out.append(text[last:m.start])
        sur = surrogates.surrogate(m.entity_type, m.value)
        out.append(sur)
        if req_id:
            audit.log_event(req_id, m.entity_type, m.value, sur)
        last = m.end
    out.append(text[last:])
    return "".join(out)


def deanonymize_text(text: str) -> str:
    """Reverse all known surrogates found in text. Uses vault reverse lookup."""
    if not text:
        return text
    changed = True
    iterations = 0
    result = text
    while changed and iterations < 3:
        changed = False
        iterations += 1
        for _, real, sur in vault.all_surrogates():
            if sur and sur in result:
                result = result.replace(sur, real)
                changed = True
    return result
