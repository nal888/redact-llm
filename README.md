# redact-llm

```
 ██████╗ ███████╗██████╗  █████╗  ██████╗████████╗
 ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
 ██████╔╝█████╗  ██║  ██║███████║██║        ██║
 ██╔══██╗██╔══╝  ██║  ██║██╔══██║██║        ██║
 ██║  ██║███████╗██████╔╝██║  ██║╚██████╗   ██║
 ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝
```

Transparent anonymization proxy for Claude Code in penetration testing engagements.

Sits between Claude Code and the Anthropic API. Every message, bash output, file read, and grep result is anonymized before leaving your machine. Responses are deanonymized before Claude Code sees them. Claude never touches real client data.

Inspired by [zeroc00I/LLM-anonymization](https://github.com/zeroc00I/LLM-anonymization). This is my implementation of that design.

> 🎓 **Student / learning project.** Built to explore how to safely use
> cloud AI during pentest work. Not a production tool — lab-tested only,
> not run on real engagement traffic. Expect rough edges.
>
> ⚠️ **For research, education, and authorized security testing only.**
> Use only where you have **explicit written permission** — your own lab,
> your own assets, a CTF, a bug bounty scope, or a signed pentest contract.
> Do not use this tool on infrastructure you don't own or aren't contracted
> to test. The author is not responsible for misuse.

## How It Works in Practice

You use Claude Code exactly as you normally would — the proxy is invisible. All sensitive data is stripped before it reaches Anthropic and restored before Claude Code sees the response.

```bash
# Claude Code runs nmap and gets real output back
$ claude
> run nmap -sV -sC against 10.20.0.0/24 and tell me what you find

# What Claude actually sees (surrogates):
#   "Nmap scan report for host-0042 (203.0.113.12)"
#   "OpenSSH 8.2 running on host-0042"

# What you see in your terminal (real data restored):
#   "Nmap scan report for dc01.acmecorp.local (10.20.0.10)"
#   "OpenSSH 8.2 running on dc01.acmecorp.local"
```

Claude reasons about the surrogates and its answers come back with surrogates too — the proxy deanonymizes them before they reach your terminal. Claude never knows the real target name, IPs, or credentials.

### What stays protected

- Every bash command output (nmap, crackmapexec, mimikatz, etc.)
- Every file read by Claude Code
- Every grep result, every log snippet
- Credentials you paste into the conversation
- Hostnames, usernames, org names you type directly

### What you still need to handle

- Files you share outside the Claude Code session (reports, notes)
- Screenshots
- Data you copy-paste into other tools

## Architecture

```
  ┌─────────────┐            ┌─────────────┐           ┌──────────────┐
  │ claude CLI  │ ──http──►  │  redact-llm │ ──https─► │  Anthropic   │
  │ (you)       │ ◄──http──  │   proxy     │ ◄──https─ │     API      │
  └─────────────┘            └─────┬───────┘           └──────────────┘
                                   │
                          ┌────────▼────────┐
                          │  SQLite vault   │
                          │  real ↔ fake    │
                          │ (per engagement)│
                          └─────────────────┘
```

Inside the proxy:

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR MACHINE                             │
│                                                                 │
│  Claude Code                                                    │
│      │  ANTHROPIC_BASE_URL=http://localhost:8181                │
│      ▼                                                          │
│  redact-llm  (FastAPI :8181)                                    │
│      │                                                          │
│      ├─ Layer 1: Regex detector                                 │
│      │   └─ Deterministic: IPs, CIDRs, hashes, MACs,            │
│      │      emails, domains, tokens, AWS keys, JWTs,            │
│      │      AD\user, SIDs, LDAP DNs, UNC paths, SSH keys        │
│      │                                                          │
│      ├─ Layer 2: LLM detector (Ollama qwen3:4b)                 │
│      │   └─ Understands context: bare hostnames, person         │
│      │      names, org names, codenames, cleartext creds        │
│      │                                                          │
│      ├─ PII Vault (SQLite)                                      │
│      │   └─ Persistent surrogate mappings per engagement        │
│      │      original ←→ surrogate, isolated by client           │
│      │                                                          │
│      ├─ Pre-send scanner                                        │
│      │   └─ Final-pass check before the request leaves;         │
│      │      warn or block on unexpected entities                │
│      │                                                          │
│      ├─ Audit log (SQLite, append-only)                         │
│      │   └─ Real values stored as HMAC hashes                   │
│      │                                                          │
│      ▼  [only surrogates leave the machine]                     │
│                                                                 │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
                                   ▼
                         Anthropic API (Claude)
                         sees only fake data
```

Surrogates are HMAC-SHA256-keyed per engagement, so the same real value always maps to the same fake within an engagement (prompt cache survives, cross-turn references stay consistent).

Responses are deanonymized on the way back: SSE stream is parsed, text and tool-use JSON are reverse-looked-up against the vault, real values are restored before Claude Code sees them.

### Request / response flow in detail

Every request Claude Code makes is a `POST /v1/messages` with a JSON body. The proxy walks every text-bearing field:

- `messages[*].content` (your messages + tool results you ran)
- `messages[*].content[*].text` (text blocks)
- `messages[*].content[*].input` (tool-use inputs that contain real data)
- `messages[*].content[*].content` (tool_result content)
- `system[*].text` (Claude Code's system prompt, which also contains your email + memory)

For each string found, regex is run first. Any match is replaced inline with a surrogate from the vault (or a new one is minted and stored). Then the remaining text is optionally passed to Ollama for LLM-based extraction of bare hostnames / names / org names / passwords / codenames. LLM matches that don't overlap regex matches are also swapped.

The modified body is then re-serialized and forwarded to Anthropic over HTTPS.

### On the way back

The response is Server-Sent Events (SSE). The proxy:

1. Decompresses the stream (Anthropic often responds with `Content-Encoding: gzip`).
2. Parses frames: `message_start`, `content_block_start`, `content_block_delta` (text or tool_use JSON), `content_block_stop`, `message_delta`, `message_stop`.
3. Buffers text deltas per content block until `content_block_stop`, then runs deanonymization (substring replace of known surrogates → real values). This avoids splitting a surrogate across chunks.
4. Buffers tool-use `input_json_delta` the same way and parses the full JSON at block-stop before deanonymizing.
5. Re-emits corrected deltas to Claude Code.

Thinking / signature blocks are passed through untouched (rewriting them would break Anthropic's verification).

### Fingerprint + attestation handling

Claude Code embeds a `cc_version` fingerprint and a native `cch=` attestation hash in the system prompt. The fingerprint is a 3-char SHA-256 of salt + chars [4, 7, 20] of the first user message + CLI version. When we modify the first user message, the fingerprint no longer matches. The proxy:

- Recomputes `cc_version` against the modified message using an algorithm derived from testing.
- Strips the `cch=...;` block entirely (it's a native binary hash we can't recompute; Anthropic also accepts SDK requests without it).

Without these two fixes, requests would either be logged with a wrong attribution (fingerprint mismatch) or rejected as tampered (cch mismatch, if that path is enforced).

## What gets anonymized

| Type | Example | Detected by |
|---|---|---|
| IPv4 / IPv6 | `10.10.50.5`, `fe80::1` | Regex |
| CIDR ranges | `10.10.0.0/16` | Regex |
| Hashes (MD5/SHA1/SHA256/NTLM) | `8846f7eaee8fb117...` | Regex |
| MAC addresses | `aa:bb:cc:dd:ee:ff` | Regex |
| Email addresses | `john@contoso.com` | Regex |
| Domains / FQDNs | `dc01.contoso.local` | Regex |
| URLs | `https://intranet.contoso.com` | Regex |
| AWS / cloud tokens | `AKIAIOSFODNN7EXAMPLE`, ARNs | Regex |
| JWTs, API keys, session tokens | `eyJhbGci...`, `sk_live_...`, `ghp_...`, `xoxb-...` | Regex |
| SSH private keys | `-----BEGIN OPENSSH...` | Regex |
| AD usernames | `CONTOSO\jsmith` | Regex |
| Windows SIDs | `S-1-5-21-...` | Regex |
| LDAP DNs | `CN=Admin,DC=acme,DC=corp` | Regex |
| UNC paths | `\\FILE01\share` | Regex |
| Phone numbers, Luhn-valid credit cards | `+1-555-...`, `4111-1111-...` | Regex |
| UUIDs | `550e8400-...` | Regex |
| Conventional hostnames | `DC01`, `WEB02`, `SQL03` | Regex |
| Bare hostnames | `FILESERVER-PRD`, `KALI-LAB` | LLM |
| Cleartext passwords | `C0nt0s0@2024!` | LLM |
| Organization names | `Contoso Corporation` | LLM (+ `X Corp/Inc/Ltd` regex) |
| Person names | `John Smith` | LLM |
| Internal project codenames | `Operation Phoenix` | LLM |

## Surrogate format

Surrogates are realistic-looking but clearly non-routable:

| Type | Original | Surrogate |
|---|---|---|
| IP | `192.168.1.10` | `203.0.113.47` (RFC 5737 TEST-NET) |
| Domain | `contoso.local` | `xkqpzt.pentest.local` |
| Hostname | `DC01` | `host-0042` |
| Username | `CONTOSO\jsmith` | `PENTEST\u8ab2f3` |
| Email | `john@contoso.com` | `rfkwma@example.pentest` |
| Hash | `8846f7ee...` (32 chars) | random 32-char hex |
| Credential | `C0nt0s0@2024!` | `[REDACTED_CRED_XK9A2B3C]` |
| Person name | `John Smith` | `Jordan Tran` |
| Org name | `Acme Corporation` | `PentestCorp-AB12` |

Mappings persist across sessions in SQLite. The same original always maps to the same surrogate within an engagement.

## Quick Start

One-time install:

```bash
git clone https://github.com/nal888/redact-llm.git
cd redact-llm
./scripts/install.sh
```

The installer creates a venv, installs Python deps, offers to install [Ollama](https://ollama.com), pulls the default model (`qwen3:4b-instruct-2507-q4_K_M`), and symlinks `redact` into `~/.local/bin`. If you decline Ollama, the proxy runs in regex-only mode.

### Option A: Local (primary)

```bash
redact start acme-2026-q2     # start proxy in background
redact claude                  # launch Claude Code through the proxy
redact stop                    # stop when done
```

### Option B: VPS (proxy on remote machine, tunnel from laptop)

**On VPS** (once):
```bash
git clone https://github.com/nal888/redact-llm.git && cd redact-llm
./scripts/install.sh
```

**On VPS** (per engagement):
```bash
redact start acme-2026-q2
```

**On laptop**:
```bash
redact tunnel root@<vps-ip>    # terminal 1 — keep open
redact claude                   # terminal 2
```

Add `--ollama` to `redact tunnel` to also forward the Ollama port if you want the LLM layer on the VPS.

## Engagement wordlist (optional)

If you already know specific names / brands / codenames that will come up — the client's company name, project codenames, people on their team — you can give the proxy a wordlist. Every exact match gets swapped, no detection needed. This is the reliable way to cover single-word brand names the LLM might miss.

Create a file (one value per line, optional `:TYPE` suffix):

```
# acme.txt
Acme Corporation:ORG
ReanCyber:ORG
Operation Blackwing:CODENAME
John Smith:PERSON
jsmith:PERSON
internal-project-42
```

Types understood: `ORG`, `PERSON`, `CODENAME`, `HOSTNAME`, `PASSWORD`, or anything from the regex list. Lines without `:TYPE` use `CUSTOM` and get `[CUSTOM_xxxx]` as the surrogate.

Pass it when starting the proxy:

```bash
redact start acme-q2 --wordlist acme.txt
```

The path is persisted in `~/.redact/config.json`, so it's reused on subsequent starts until you pass `--wordlist ''` to clear.

### Match semantics

- **Case-insensitive**: `Acme Corporation` in the wordlist matches `ACME CORPORATION` and `acme corporation`.
- **Word-boundary-anchored**: `phoenix` matches the word `phoenix` on its own but NOT inside `phoenixville` or `myphoenixapp`.
- **Ordering**: regex patterns run first, wordlist second. Composite entities (e.g. `CONTOSO\jsmith` matched as `AD_USER`) take priority over their substring components — if `jsmith` is in the wordlist, it still gets anonymized when standalone, but inside an AD-user match the whole `CONTOSO\jsmith` is anonymized as one unit.
- **Per-case vault entries**: `ACME` and `acme` in the same text produce separate vault entries (different surrogates). The original casing is preserved on deanonymization (no information loss), but it means each casing variant gets its own fake value.

### Wordlist tips

- If the same entity appears in multiple casings in the target's output (e.g. `Acme Corporation` in one scan and `ACME CORP` in another), add each casing as its own line — otherwise they'll get different surrogates.
- Shorter values = more chances for accidental matches despite word boundaries. A 3-letter codename like `ops` is risky; `Operation Ops` or `ProjectOps` is safer.
- Start with a narrow list at kickoff (client name + key personnel + codenames), then extend as new things come up during the engagement.

## Engagement Management

**Critical: set a unique engagement per client.** This isolates surrogate mappings so the same IP at two different clients maps to different surrogates.

```bash
redact start acme-2026-q2              # new engagement
redact vault stats                     # check counts per entity type
redact vault list                      # see all real ↔ fake mappings
redact vault find 10.20.0.10           # search a real or fake value
redact vault engagements               # list all engagements on disk
redact vault clear acme-2026-q2        # wipe an engagement's vault + key + audit
```

## CLI

```
redact start <engagement>    start proxy for an engagement
redact stop                  stop the running proxy
redact status                show proxy state + config
redact claude [args...]      launch Claude Code through the proxy
redact run -- <cmd>          run any command through the proxy
redact logs [-f]             tail proxy logs
redact tunnel <user@vps>     SSH tunnel laptop → VPS proxy
redact vault <subcommand>    inspect vault (list, find, stats, …)
redact config <show|set>     view or change persisted defaults
```

Run `redact <command> -h` for flags and examples.

## Pre-send scanner

After anonymization, the proxy runs a final-pass regex scan on the fully-serialized outgoing JSON body. If any high-sensitivity pattern matches something that isn't a known surrogate or a whitelisted value (Anthropic domains, Claude Code session IDs), it's treated as a potential leak.

Three modes (`PRESEND_MODE` env or `--presend` flag):

- `warn` (default) — log the finding, send the request anyway. Good for development and for learning what your workflow actually produces.
- `block` — refuse to send. Returns `HTTP 451` to Claude Code. Safe mode for strict engagements.
- `off` — skip the scanner entirely.

The log line is one line per request summarizing how many and which entity types were flagged. Values are HMAC-hashed in the log — tailing `redact logs` never shows real data.

In practice, this scanner produces some false positives on Claude Code's own metadata (session IDs, tool schema placeholder strings). I haven't fully tuned it; `warn` mode is fine for development, `block` is not currently safe to run on a real engagement without more tuning.

## Audit log

Every anonymized request and every entity caught is recorded in an append-only SQLite file at `~/.anon-proxy/<engagement>.audit.sqlite`. Real values are stored as HMAC hashes, not plaintext — the audit log itself cannot leak data.

```bash
curl http://localhost:8181/health                        # stats
curl http://localhost:8181/audit/export > audit.csv      # full export
```

Schema:

- `requests` — one row per API call: `request_id`, `ts`, `engagement_id`, `method`, `path`, `status`, `bytes_in`, `bytes_out`, `entities_found`.
- `events` — one row per entity swapped: `request_id`, `ts`, `entity_type`, `real_hash` (HMAC-SHA256 truncated), `surrogate`.

To reconcile an audit hash with the vault, look up the surrogate in the vault for that engagement — the mapping is one-to-one deterministic within the engagement.

## Configuration

Config lives in `~/.redact/config.json`. CLI flags override.

| Key | Default | Description |
|---|---|---|
| `port` | `8181` | Proxy listen port |
| `model` | `qwen3:4b-instruct-2507-q4_K_M` | Ollama model |
| `llm_detector` | `true` | Enable LLM layer |
| `presend_mode` | `warn` | `off` / `warn` / `block` |
| `engagement` | — | Last engagement used |

Proxy-level via env: `VAULT_DIR`, `OLLAMA_HOST`, `LLM_TIMEOUT`, `UPSTREAM_URL`, `ENGAGEMENT_ID`, `LLM_MODEL`, `PRESEND_MODE`.

### Full env reference

| Variable | Default | Description |
|---|---|---|
| `ENGAGEMENT_ID` | `default` | Isolates vault + HMAC key per client. |
| `VAULT_DIR` | `~/.anon-proxy` | Directory holding `<engagement>.sqlite`, `.key`, `.audit.sqlite`. |
| `UPSTREAM_URL` | `https://api.anthropic.com` | API endpoint to forward to. |
| `PORT` | `8181` | Proxy listen port. |
| `LLM_DETECTOR` | `true` | Enable/disable the LLM layer. |
| `LLM_MODEL` | `qwen3:4b-instruct-2507-q4_K_M` | Ollama model name. |
| `LLM_TIMEOUT` | `15` | Per-call LLM timeout in seconds (circuit breaker trips after 3 consecutive failures). |
| `LLM_MIN_LEN` | `20` | Skip LLM on strings shorter than this. |
| `LLM_MAX_LEN` | `4000` | Truncate LLM input to this many chars. |
| `LLM_REGEX_SKIP` | `0.25` | Skip LLM if regex already covers ≥ this fraction of the text. |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama endpoint. |
| `PRESEND_MODE` | `warn` | `off` / `warn` / `block`. |

### Per-engagement files

Each engagement creates three files in `$VAULT_DIR`:

- `<engagement>.sqlite` — vault: real ↔ fake mappings.
- `<engagement>.key` — 32-byte random HMAC secret. Mode 0600.
- `<engagement>.audit.sqlite` — audit log (WAL-mode).

To wipe an engagement:
```bash
redact vault clear acme-q2    # asks for confirmation
```
Or manually:
```bash
rm ~/.anon-proxy/acme-q2.*
```

## LLM model

The installer pulls **one** model: `qwen3:4b-instruct-2507-q4_K_M` (~2.5 GB). That's what the proxy uses by default. You don't need to download anything else.

If you want to try a different model, pass `--model <name>` to `redact start` (the model must already be pulled via `ollama pull`).

## Running Tests

```bash
.venv/bin/pytest tests/ -v
```

80 unit tests covering detector / surrogates / vault / anonymizer / audit. Not end-to-end pentest-fixture leak tests.

## Troubleshooting

**`redact claude` says "API Error: The socket connection was closed unexpectedly"**
The proxy isn't running, but `ANTHROPIC_BASE_URL` is still set. Either start it (`redact start <engagement>`) or unset the env var.

**`redact start` says "venv missing"**
Run `./scripts/install.sh` from the repo root. You're probably running `redact` before the install completed, or the venv got deleted.

**LLM detection is very slow (20-60 s for the first request)**
Cold start — Ollama loads the model on demand. The proxy does a warmup in the background when it starts, so wait ~30 s after `redact start` before the first `redact claude` call. Also check `OLLAMA_KEEP_ALIVE`: set it to `1h` if your model keeps unloading.

**Pre-send scanner flags lots of entities per request**
Most are Claude Code's own metadata (session IDs, tool schema placeholder strings, etc.), not real leaks. I haven't fully tuned this down. Set `PRESEND_MODE=off` if the noise is distracting.

**Claude comments on "203.0.113.x is TEST-NET-3"**
Cosmetic. Claude sometimes recognizes the RFC 5737 surrogate range. Doesn't affect correctness.

**An entity I expected isn't in the vault**
- LLM layer may be off — check `redact status` shows `llm: on`.
- The model may not be pulled — `ollama list | grep qwen`.
- Single-word brand names (e.g. `ReanCyber`) are a known gap — sometimes the LLM catches them, sometimes not.

**Switching engagements**
`redact start` reuses the last engagement if you don't pass a name. To switch: `redact stop && redact start new-name`.

## Limitations

- **Not yet run against real engagement traffic.** Tested in a lab with synthetic pentest data and against the author's own site. Treat as beta until it's seen a real client engagement — real data has edge cases labs don't cover (entity types you didn't think of, surrogate formats splitting across JSON boundaries, workflow interruptions you can't predict).
- **Regex misses contextual data**: bare hostnames (`DC01`), single-word org names (`ReanCyber`), cleartext passwords in unusual formats — the LLM layer is essential for these, and the 4 B model misses some.
- **Screenshots, PDFs, images pass through untouched**: the proxy only sees text in the JSON body. Redact images separately before sharing.
- **No provable privacy guarantee**: correlation attacks on writing style, request timing, or account-level metadata are out of scope. This tool prevents content-level data exposure, not metadata.
- **Surrogate collision risk is low but non-zero**: two different originals getting the same surrogate (probabilistically unlikely within an engagement).
- **Not a substitute for contract review**: always verify what your NDA/MSA allows before using cloud AI on client engagements. Anonymized data still goes to Anthropic.
- **Claude sometimes notices surrogates**: `.pentest.local` and `203.0.113.x` are recognizable as test/doc ranges. Cosmetic, doesn't affect correctness.
- **Pre-send scanner has false positives**: Claude Code metadata (session IDs, tool schema fields) can trip alerts in `warn` mode.

## Credits

Architectural approach is from [zeroc00I/LLM-anonymization](https://github.com/zeroc00I/LLM-anonymization) — regex + LLM, per-engagement vault, HMAC-keyed surrogates, RFC 5737 IPs, `.pentest.local` domains, SSE streaming. Their repo at the time of writing is a design document; this is my implementation.

Also informed by [Microsoft Presidio](https://microsoft.github.io/presidio/), [Protect AI LLM Guard](https://protectai.github.io/llm-guard/), and the [LiteLLM + Presidio bugs on the Anthropic native path](https://github.com/BerriAI/litellm/issues/22821).

## License

MIT. See [LICENSE](./LICENSE).
