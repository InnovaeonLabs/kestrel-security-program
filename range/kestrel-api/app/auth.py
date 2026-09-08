"""Authentication for the Kestrel Pay API.

INTENTIONALLY VULNERABLE (lab). Two classic API auth flaws are present so the
detection pipeline has something real to catch, and so the remediation/retest
phase can show a fix in the same codebase via KESTREL_HARDENED=1:

  * OWASP API2 (Broken Authentication): accepts JWTs signed with alg=none, and
    uses a weak, hardcoded HS256 secret (also a planted secret for gitleaks).
  * MFA is simulated; login telemetry supports MFA-fatigue / impossible-travel
    detections downstream.

When KESTREL_HARDENED=1: alg is pinned to HS256, alg=none is rejected, and the
secret is read from the environment (no hardcoded fallback).
"""
from __future__ import annotations

import os
import jwt  # PyJWT

from . import telemetry

# --- Planted weak secret (VULN). gitleaks/Semgrep should flag this in CI. ---
_HARDCODED_SECRET = "kestrel-dev-secret"  # lab-intentional: intentional weak secret
HARDENED = os.environ.get("KESTREL_HARDENED", "0") == "1"


def _secret() -> str:
    if HARDENED:
        s = os.environ.get("KESTREL_JWT_SECRET")
        if not s:
            raise RuntimeError("KESTREL_JWT_SECRET required in hardened mode")
        return s
    return _HARDCODED_SECRET


def issue_token(username: str, role: str) -> str:
    return jwt.encode({"sub": username, "role": role}, _secret(), algorithm="HS256")


def verify_token(token: str, src_ip: str = "-") -> dict | None:
    """Return claims if valid, else None. VULN in default mode: allows alg=none."""
    if HARDENED:
        try:
            return jwt.decode(token, _secret(), algorithms=["HS256"])
        except jwt.InvalidTokenError:
            telemetry.emit("auth_token_invalid", outcome="failure", src_ip=src_ip,
                           severity="low", technique="T1550.001")
            return None
    # --- VULNERABLE PATH ---
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg", "").lower() == "none":
            claims = jwt.decode(token, options={"verify_signature": False},
                                algorithms=["none"])
            telemetry.emit("auth_alg_none_accepted", outcome="success", src_ip=src_ip,
                           actor=claims.get("sub", "-"), severity="high",
                           technique="T1550.001", alg="none")
            return claims
        return jwt.decode(token, _secret(), algorithms=["HS256"])
    except jwt.InvalidTokenError:
        telemetry.emit("auth_token_invalid", outcome="failure", src_ip=src_ip,
                       severity="low", technique="T1110")
        return None


def check_login(username: str, password: str, mfa_code: str | None,
                src_ip: str, user_agent: str) -> tuple[bool, str]:
    """Synthetic login. Any non-empty password 'works' for a known user in the
    lab; the point is realistic *telemetry*, not credential strength. MFA is
    simulated: code '000000' is treated as a rejected/fatigued push."""
    from .db import connect
    with connect() as conn:
        row = conn.execute("SELECT role, mfa_enabled FROM users WHERE username=?",
                           (username,)).fetchone()
    if not row or not password:
        telemetry.emit("login_failure", outcome="failure", actor=username, src_ip=src_ip,
                       user_agent=user_agent, severity="low", technique="T1110")
        return False, ""
    if row["mfa_enabled"] and mfa_code == "000000":
        telemetry.emit("mfa_denied", outcome="failure", actor=username, src_ip=src_ip,
                       user_agent=user_agent, severity="medium", technique="T1621",
                       reason="user_denied_push")
        return False, ""
    telemetry.emit("login_success", outcome="success", actor=username, src_ip=src_ip,
                   user_agent=user_agent, severity="info", technique="T1078",
                   role=row["role"], mfa_used=bool(row["mfa_enabled"]))
    return True, row["role"]
