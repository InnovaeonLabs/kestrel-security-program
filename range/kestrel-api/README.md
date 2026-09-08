# Kestrel Pay API (lab target)

A small, **intentionally vulnerable** FastAPI service standing in for Kestrel Pay's payments/invoicing product. It
exists to (a) produce realistic application/API telemetry and (b) give the detection + IR + purple-team phases real
weaknesses to attack, detect, and remediate. **Synthetic data only. Do not deploy.**

## Run
```bash
# Container (preferred):
docker compose up -d kestrel-api nginx        # → http://localhost:8080
# Or locally:
pip install -r requirements.txt && uvicorn app.main:app --port 8080
# Remediated build (used in the retest phase):
KESTREL_HARDENED=1 docker compose up -d kestrel-api nginx
```
Telemetry (JSONL) is written to `range/data/logs/app.jsonl`; nginx access logs to `range/data/logs/access.log`.

## Intentional weaknesses → mapping
| Endpoint | Weakness | OWASP | ATT&CK | Detection (later phase) |
|---|---|---|---|---|
| `POST /login` | credential + MFA-fatigue telemetry source | API2 | T1078/T1110/T1621 | impossible-travel, MFA-fatigue burst |
| `GET /payouts/{id}` | **IDOR / BOLA** — no object-level authz | API1 | T1190 | payout enumeration / cross-owner access |
| `GET /merchants/search?q=` | **SQL injection** (string concat) | API8 | T1190 | SQLi pattern + query error spike |
| `POST /invoices/{id}/bank` | fraudulent **bank-detail change** (BEC) | API5 | T1114 | invoice bank-change anomaly |
| `GET /fetch-logo?url=` | **SSRF** to internal/metadata | API7 | T1190 | SSRF to internal target |
| `GET /admin/export` | **bulk export** (insider/exfil) | API3 | T1074/T1567 | bulk-export volume |
| `POST /copilot` | **LLM prompt injection** + insecure tools | LLM01/LLM06 | T1552/T1059/T1213 | injection pattern + out-of-policy tool call |
| `app/auth.py` | **JWT alg=none** + hardcoded weak secret | API2 | T1550.001 | alg=none accepted; gitleaks in CI |

## Remediation toggle
`KESTREL_HARDENED=1` enables the fixed behavior for each item (object-level authz, parameterized queries, alg pinning,
env-based secret, SSRF allow-listing, copilot input/output guards + tool scoping). This lets the purple-team/retest
phase demonstrate a real before→after in one codebase.

## LLM copilot backend (real local model or mock)
The `/copilot` endpoint runs a real local model when you want one, and a deterministic mock otherwise — the
**detection is backend-agnostic** (input injection patterns + output-side secret scanning), so it catches a genuinely
jailbroken model, not just the stub.

| Env | Default | Meaning |
|---|---|---|
| `KESTREL_LLM` | `mock` | `mock` (no deps) or `ollama` (real local model) |
| `KESTREL_LLM_URL` | `http://localhost:11434` | Ollama endpoint |
| `KESTREL_LLM_MODEL` | `llama3.2:1b` | any pulled Ollama model |
| `KESTREL_LLM_TIMEOUT` | `60` | request timeout (s) |

Enable a real model (needs ~1.5–2 GB free RAM for a 1B model):
```bash
# install Ollama (https://ollama.com), then:
ollama pull llama3.2:1b
KESTREL_LLM=ollama KESTREL_HARDENED=0 uvicorn app.main:app --port 8080   # vulnerable, real model
KESTREL_LLM=ollama KESTREL_HARDENED=1 uvicorn app.main:app --port 8080   # guarded, real model
```
If Ollama is unreachable the copilot **falls back to the mock** (emits `copilot_backend_fallback`) so the range never
breaks. Detection events (`copilot_injection_suspected`, `copilot_system_prompt_leak`, `copilot_tool_call`) fire the
same way against either backend → detection **KP-0016**.

## Telemetry schema
Normalized fields shared across all sources (so Sigma rules stay portable):
`ts, source, event_type, action, outcome, actor, src_ip, user_agent, session_id, http_method, http_path, http_status,
object_type, object_id, owner, severity, technique, details{}`. See `app/telemetry.py`.
