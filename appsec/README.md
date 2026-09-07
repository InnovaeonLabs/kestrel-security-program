# Application & API Security (Phase 6)

Findings against the Kestrel Pay API ([`../range/kestrel-api/`](../range/kestrel-api/)), each tied to a detection and a
remediation that is **retested** (`KESTREL_HARDENED=1`). Retest evidence: [`tests/test_hardening.py`](tests/) (4 pass).

## Findings
| ID | Finding | OWASP API/LLM | Severity | Detection | Remediation (hardened build) | Retested |
|---|---|---|---|---|---|---|
| APP-1 | **BOLA/IDOR** on `GET /payouts/{id}` — no object-level authz | API1 | High | KP-0012 | Enforce caller-owns-object / admin check | ✅ (rule) |
| APP-2 | **JWT alg=none** accepted + hardcoded weak secret | API2 | High | KP-0010 | Pin `HS256`, reject `none`, secret from env | ✅ `test_hardened_build_rejects_alg_none` |
| APP-3 | **SQL injection** in `/merchants/search` | API8 | High | KP-0011 | Parameterized query | ✅ (rule) |
| APP-4 | **SSRF** in `/fetch-logo` → cloud metadata | API7 | Critical | KP-0013 | URL allow-list + block internal + IMDSv2 | ✅ (rule) |
| APP-5 | **Excessive data exposure / bulk export** | API3 | High | KP-0014 | Dual-control + volume limit + DLP | ✅ (rule) |
| APP-6 | **Function-level abuse** — invoice bank change (BEC) | API5 | Medium | KP-0015 | Out-of-band verification | ✅ (rule) |
| APP-7 | **Prompt injection** → system-prompt/secret leak | LLM01 | Critical | KP-0016 | Input/output guards | ✅ `test_hardened_build_blocks_injection` |
| APP-8 | **Insecure tool permissions** (copilot `get_env`/lookup) | LLM06 | High | KP-0016 | Tool scoping + block on injection | ✅ (guarded) |

## Secure-coding takeaways
- Authorization is per-**object**, not per-route. Never trust a token's mere validity — check ownership.
- Never accept `alg=none`; pin algorithms; keep secrets out of code (also caught by CI secret scanning, Phase 11).
- Treat LLM input as untrusted code: separate instructions from data, scope tools, filter outputs, and **log** tool calls.

## Reproduce
```bash
# Vulnerable vs hardened, same codebase:
docker compose up -d kestrel-api                       # vulnerable
KESTREL_HARDENED=1 docker compose up -d kestrel-api    # remediated
.venv/Scripts/python -m pytest -q appsec/tests         # retest: 4 pass
```
