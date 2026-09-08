"""Kestrel Pay API — the vulnerable product under test (lab).

Intentional weaknesses (each maps to an OWASP API/ATT&CK item and a detection):
  /login                      -> auth + MFA telemetry (T1078/T1110/T1621)
  GET /payouts/{id}           -> IDOR / BOLA, no object-level authz (API1, T1190)
  GET /merchants/search       -> SQL injection via string concat (API8, T1190)
  POST /invoices/{id}/bank    -> fraudulent bank-detail change (BEC, API5)
  GET /fetch-logo?url=        -> SSRF to internal metadata (API7, T1190)
  GET /admin/export           -> bulk data export (insider/exfil, T1074/T1567)
  POST /copilot               -> LLM prompt injection (LLM01, T1552/T1059)

Set KESTREL_HARDENED=1 to enable the remediated behavior (used in the retest phase).
Run:  uvicorn app.main:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import os
import urllib.request

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import auth, copilot, telemetry
from .db import connect, init_and_seed

HARDENED = os.environ.get("KESTREL_HARDENED", "0") == "1"
app = FastAPI(title="Kestrel Pay API", version="1.0-lab")


@app.on_event("startup")
def _startup():
    if os.environ.get("KESTREL_SEED", "1") == "1":
        init_and_seed()


@app.middleware("http")
async def access_log(request: Request, call_next):
    src_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "-")
    resp = await call_next(request)
    telemetry.emit("http_request", action=request.method, outcome="success",
                   src_ip=src_ip, user_agent=request.headers.get("user-agent", "-"),
                   http_method=request.method, http_path=str(request.url.path),
                   http_status=resp.status_code, severity="info")
    return resp


def _ip(r: Request) -> str:
    return r.headers.get("x-forwarded-for", r.client.host if r.client else "-")


class LoginIn(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None


@app.post("/login")
def login(body: LoginIn, request: Request):
    ok, role = auth.check_login(body.username, body.password, body.mfa_code,
                                _ip(request), request.headers.get("user-agent", "-"))
    if not ok:
        raise HTTPException(401, "authentication failed")
    return {"token": auth.issue_token(body.username, role), "role": role}


@app.get("/payouts/{payout_id}")
def get_payout(payout_id: int, request: Request):
    """VULN (API1/BOLA): returns any payout regardless of the caller's ownership."""
    claims = auth.verify_token((request.headers.get("authorization", "") or "").removeprefix("Bearer ").strip(),
                               src_ip=_ip(request))
    actor = (claims or {}).get("sub", "anonymous")
    with connect() as conn:
        row = conn.execute(
            "SELECT p.*, m.owner_user_id FROM payouts p JOIN merchants m ON m.id=p.merchant_id WHERE p.id=?",
            (payout_id,)).fetchone()
    if not row:
        raise HTTPException(404, "not found")
    owner = str(row["owner_user_id"])
    if HARDENED:
        # Remediated: enforce object-level authorization.
        caller_id = {"ava.reyes": "2", "leo.kim": "3", "ivy.shah": "4"}.get(actor)
        if claims and claims.get("role") != "admin" and caller_id != owner:
            telemetry.emit("authz_denied", outcome="blocked", actor=actor, src_ip=_ip(request),
                           object_type="payout", object_id=str(payout_id), owner=owner,
                           severity="medium", technique="T1190")
            raise HTTPException(403, "forbidden")
    telemetry.emit("object_access", action="read_payout", outcome="success", actor=actor,
                   src_ip=_ip(request), object_type="payout", object_id=str(payout_id),
                   owner=owner, severity="low", technique="T1190",
                   authz="enforced" if HARDENED else "MISSING",
                   amount_cents=row["amount_cents"])
    return {k: row[k] for k in row.keys()}


@app.get("/merchants/search")
def search_merchants(q: str, request: Request):
    """VULN (API8): SQL injection via string concatenation."""
    actor = "anonymous"
    with connect() as conn:
        if HARDENED:
            rows = conn.execute("SELECT id,name,country FROM merchants WHERE name LIKE ?",
                                (f"%{q}%",)).fetchall()
        else:
            query = f"SELECT id,name,country FROM merchants WHERE name LIKE '%{q}%'"  # lab-intentional
            suspicious = any(t in q.lower() for t in ["'", "union", "--", " or ", "1=1", ";"])
            telemetry.emit("db_query", action="search", outcome="success", actor=actor,
                           src_ip=_ip(request), object_type="merchant", severity="high" if suspicious else "info",
                           technique="T1190", sqli_suspected=suspicious, query=query[:300])
            try:
                rows = conn.execute(query).fetchall()
            except Exception as exc:  # SQL error is itself a signal
                telemetry.emit("db_query_error", outcome="failure", actor=actor, src_ip=_ip(request),
                               severity="high", technique="T1190", error=str(exc)[:200])
                raise HTTPException(400, "query error")
    return [dict(r) for r in rows]


class BankChange(BaseModel):
    dest_bank_last4: str


@app.post("/invoices/{invoice_id}/bank")
def change_bank(invoice_id: int, body: BankChange, request: Request):
    """BEC target: change of payout bank details on an invoice."""
    actor = (auth.verify_token((request.headers.get("authorization","") or "").removeprefix("Bearer ").strip(),
             src_ip=_ip(request)) or {}).get("sub", "anonymous")
    with connect() as conn:
        old = conn.execute("SELECT dest_bank_last4 FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        if not old:
            raise HTTPException(404, "not found")
        conn.execute("UPDATE invoices SET dest_bank_last4=? WHERE id=?", (body.dest_bank_last4, invoice_id))
    telemetry.emit("invoice_bank_change", outcome="success", actor=actor, src_ip=_ip(request),
                   object_type="invoice", object_id=str(invoice_id), severity="high",
                   technique="T1114", old_last4=old["dest_bank_last4"], new_last4=body.dest_bank_last4)
    return {"invoice": invoice_id, "dest_bank_last4": body.dest_bank_last4}


@app.get("/fetch-logo")
def fetch_logo(url: str, request: Request):
    """VULN (API7 SSRF): fetches an attacker-supplied URL server-side."""
    actor = "anonymous"
    internal = any(h in url for h in ["169.254.169.254", "localhost", "127.0.0.1", "metadata", "10.", "172.", "192.168."])
    telemetry.emit("ssrf_fetch", outcome="success", actor=actor, src_ip=_ip(request),
                   http_path="/fetch-logo", severity="critical" if internal else "medium",
                   technique="T1190", target_url=url, internal_target=internal)
    if HARDENED:
        if internal or not url.startswith("https://"):
            telemetry.emit("ssrf_blocked", outcome="blocked", actor=actor, src_ip=_ip(request),
                           severity="medium", technique="T1190", target_url=url)
            raise HTTPException(400, "url not allowed")
    if HARDENED:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:  # lab-intentional: hardened validates above
                return {"fetched_bytes": len(r.read(1024))}
        except Exception:
            raise HTTPException(502, "fetch failed")
    # VULN: simulate the fetch result without egress (safe in lab), including a fake IMDS hit.
    if internal:
        return {"simulated": True, "note": "SSRF reached internal target (lab-simulated)",
                "sample": "iam-role: kestrel-api-task (lab)"}
    return {"simulated": True, "url": url}


@app.get("/admin/export")
def bulk_export(request: Request):
    """Bulk export of customer data (insider / exfil path)."""
    actor = (auth.verify_token((request.headers.get("authorization","") or "").removeprefix("Bearer ").strip(),
             src_ip=_ip(request)) or {}).get("sub", "anonymous")
    with connect() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM cards").fetchone()["c"]
    telemetry.emit("bulk_export", outcome="success", actor=actor, src_ip=_ip(request),
                   object_type="cards", severity="high", technique="T1074",
                   record_count=n)
    return {"exported_records": n}


class CopilotIn(BaseModel):
    message: str
    session_id: str | None = "-"


@app.post("/copilot")
def copilot_endpoint(body: CopilotIn, request: Request):
    return copilot.handle(body.message, actor="merchant-user", src_ip=_ip(request),
                          session_id=body.session_id or "-")


@app.get("/health")
def health():
    return {"status": "ok", "hardened": HARDENED}


@app.exception_handler(HTTPException)
async def _log_http_exc(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
