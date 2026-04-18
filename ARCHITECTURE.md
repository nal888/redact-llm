# anon-proxy — Architecture

Local HTTPS-agnostic proxy that anonymizes pentest data in Claude Code traffic before it reaches Anthropic, and deanonymizes responses before they reach the user.

## Flow

```
claude CLI  ──(http://localhost:8080)──>  anon-proxy  ──(https://api.anthropic.com)──>  Anthropic
                                              ▲ ▼
                                          SQLite vault
                                         (real ↔ surrogate)
```

Claude Code is pointed at the proxy via `ANTHROPIC_BASE_URL=http://localhost:8080`. The proxy:
- Parses `POST /v1/messages` JSON body
- Walks `system[*].text`, `messages[*].content[*].text`, `tool_result` blocks
- Replaces detected entities (IPs, hashes, domains, etc.) with deterministic surrogates
- Recomputes `cc_version` fingerprint in `system[0]` to match modified first user message
- Strips `cch=...;` attestation (algorithm is in Bun native, can't recompute — request will look like a plain SDK call)
- Forwards to Anthropic, streams response back while deanonymizing surrogates → real data

## Key components

- **vault.py** — SQLite, keyed by `engagement_id`. Columns: `entity_type`, `real`, `surrogate`. Unique index on `(engagement_id, entity_type, real)`. Same real value always gets the same surrogate within an engagement.

- **surrogates.py** — HMAC-SHA256(key=engagement_secret, msg=real) → truncated for token format. Per-engagement key lives in `.env`. Generators per entity type: IP → RFC 5737 TEST-NET space, domain → `xkqpzt.pentest.local`, hostname → `host-0042`, credential → `[CRED_XK9A2B3C]`.

- **detector.py** — Regex patterns ordered by specificity. Returns `list[Match(entity_type, start, end, value)]`. Patterns cover: IPv4, CIDR, IPv6, MAC, email, domain/FQDN, URL, MD5, SHA1, SHA256, NTLM, AWS access keys, JWTs, generic API keys.

- **anonymizer.py** — Given a request body dict, walks known text locations and replaces matches in-place. Preserves cache_control, tool_use_id, all structural fields.

- **deanonymizer.py** — Reverse lookup against vault. For streaming responses, a rolling buffer per content block: emit all-but-trailing-N-chars immediately, flush remainder at `content_block_stop`.

- **adapters/anthropic.py** — Knows the Anthropic request/response shape. Entry points: `anonymize_request(body) -> body`, `deanonymize_stream(chunks) -> chunks`. Fingerprint recompute lives here.

- **server.py** — FastAPI app. One route: `POST /v1/messages`. Reads body, calls adapter, forwards with `httpx.AsyncClient`, streams back.

## Configuration

Env vars:
- `ENGAGEMENT_ID` — **must set per client**. Isolates vault rows + surrogate HMAC key.
- `ENGAGEMENT_SECRET` — HMAC key for deterministic surrogate gen. Random per engagement.
- `PORT` — proxy listen port (default 8080).
- `UPSTREAM_URL` — default `https://api.anthropic.com`.

## What v1 does NOT do

- OpenAI / Gemini adapters (Claude only)
- LLM-layer detection (regex only for v1)
- Tool use round-trip re-anonymization (tool_result on the way back up)
- Thinking block deanon (pass through untouched)
- Docker
- Multi-user vault
- Screenshot / external file redaction

## What can break

- **NATIVE_CLIENT_ATTESTATION enforcement** — if Anthropic rejects requests without valid `cch=`, stripping it breaks us. Fallback: disable attribution header entirely via `CLAUDE_CODE_DISABLE_ATTRIBUTION=true` env var when running Claude Code.
- **Surrogates splitting across SSE chunks** — handled by rolling-window buffer. Max surrogate length must be tracked.
- **Tool use with surrogates** — tool runs locally with surrogates → returns data about fake infra → tool_result leaks real data on way back up. v1 accepts this risk; v2 fixes it.
