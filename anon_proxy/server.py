"""anon-proxy FastAPI entry."""
import logging
import os
import sqlite3
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse, Response, JSONResponse, PlainTextResponse

from . import anonymizer, audit, config, detector, llm_detector, presend, vault
from .adapters import anthropic

# Load engagement wordlist if configured
if config.WORDLIST_PATH:
    detector.load_wordlist(config.WORDLIST_PATH)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("anon-proxy")

app = FastAPI(title="anon-proxy")


@app.on_event("startup")
async def _startup_summary():
    vs = vault.stats()
    as_ = audit.stats()
    log.info("─" * 60)
    log.info("anon-proxy starting")
    log.info(f"  engagement_id  : {config.ENGAGEMENT_ID}"
             + ("  ⚠️  (default — set ENGAGEMENT_ID per client!)" if config.ENGAGEMENT_ID == "default" else ""))
    log.info(f"  vault          : {config.VAULT_PATH} ({sum(vs['counts'].values())} existing mappings)")
    log.info(f"  audit          : {as_['audit_path']} ({as_['requests_logged']} prior requests)")
    log.info(f"  upstream       : {config.UPSTREAM_URL}")
    log.info(f"  presend mode   : {presend.MODE}")
    log.info(f"  llm detector   : {'on (' + llm_detector.MODEL + ')' if llm_detector.ENABLED else 'off'}")
    log.info("─" * 60)
    # Kick off LLM warmup in a thread so startup doesn't block
    import threading
    threading.Thread(target=llm_detector.warmup, daemon=True).start()

HOP_BY_HOP = {
    "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
    "accept-encoding",
}
RESPONSE_STRIP = HOP_BY_HOP | {"content-encoding"}


def _forward_headers(src) -> dict:
    return {k: v for k, v in src.items() if k.lower() not in HOP_BY_HOP}


@app.get("/health")
def health():
    return JSONResponse({"ok": True, "vault": vault.stats(), "audit": audit.stats()})


@app.get("/audit/export")
def audit_export():
    return PlainTextResponse(audit.export_csv(), media_type="text/csv")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(path: str, request: Request) -> Response:
    upstream = f"{config.UPSTREAM_URL}/{path}"
    if request.url.query:
        upstream = f"{upstream}?{request.url.query}"

    body = await request.body()
    headers = _forward_headers(request.headers)

    is_messages = request.method == "POST" and path.startswith("v1/messages")
    req_id = audit.new_request_id()
    token = None

    if is_messages and body:
        before = len(body)
        audit.log_request(req_id, request.method, path, before)
        token = anonymizer.current_request_id.set(req_id)
        body = anthropic.anonymize_request(body)

        # Count entity types caught on this request (from events logged during walk)
        try:
            c = sqlite3.connect(str(config.VAULT_DIR / f"{config.ENGAGEMENT_ID}.audit.sqlite"))
            rows = c.execute(
                "SELECT entity_type, COUNT(*) FROM events WHERE request_id=? GROUP BY entity_type",
                (req_id,),
            ).fetchall()
            c.close()
            summary = ", ".join(f"{t}×{n}" for t, n in rows) or "none"
        except Exception:
            summary = "?"
        log.info(f"[{req_id}] anonymized: {before} → {len(body)} bytes, caught: {summary}")

        # Pre-send safety scan — belt-and-suspenders
        findings, block = presend.scan(body, request_id=req_id)
        if block:
            return JSONResponse(
                status_code=451,
                content={
                    "error": "anon-proxy: pre-send scanner detected possible leak; "
                             "request blocked (PRESEND_MODE=block).",
                    "findings_count": len(findings),
                },
            )

    client = httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0))
    upstream_req = client.build_request(request.method, upstream, headers=headers, content=body)
    upstream_resp = await client.send(upstream_req, stream=True)
    if upstream_resp.status_code >= 400:
        log.warning(f"[{req_id}] upstream error {upstream_resp.status_code} for {path}")

    async def _stream() -> AsyncIterator[bytes]:
        bytes_out = 0
        try:
            if is_messages and upstream_resp.status_code == 200:
                async for chunk in anthropic.deanonymize_stream(upstream_resp.aiter_bytes()):
                    bytes_out += len(chunk)
                    yield chunk
            else:
                async for chunk in upstream_resp.aiter_bytes():
                    bytes_out += len(chunk)
                    yield chunk
        finally:
            await upstream_resp.aclose()
            await client.aclose()
            if is_messages:
                try:
                    c = sqlite3.connect(
                        str(config.VAULT_DIR / f"{config.ENGAGEMENT_ID}.audit.sqlite")
                    )
                    cnt = c.execute(
                        "SELECT COUNT(*) FROM events WHERE request_id=?", (req_id,)
                    ).fetchone()[0]
                    c.close()
                except Exception:
                    cnt = 0
                audit.log_response(req_id, upstream_resp.status_code, bytes_out, cnt)
                # Intentionally skip ContextVar reset — streaming runs in a different
                # asyncio context than where we set it, and unset happens naturally
                # when the request context exits.

    resp_headers = {k: v for k, v in upstream_resp.headers.items()
                    if k.lower() not in RESPONSE_STRIP}
    return StreamingResponse(
        _stream(),
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )
