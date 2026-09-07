"""SCATTERED SABLE — controlled, benign adversary emulation.

A single financially-motivated intrusion chain against Kestrel Pay. It produces
the exact telemetry a live attack would, so detections fire and an incident can
be investigated end-to-end. SAFE BY DESIGN: no real exploitation, no third party,
no malware — it writes normalized telemetry events (and, with --live, sends benign
HTTP requests to your own running range).

Chain (each step -> ATT&CK technique -> detection ID):
  1  Identity: MFA fatigue push-bombing        T1621        -> KP-0001
  2  Identity: coerced approval + token theft   T1550.001    -> KP-0002
  3  Endpoint: encoded PowerShell stager        T1059.001    -> KP-0020
  4  Endpoint: LOLBin C2 beacon                 T1071        -> KP-0021
  5  Endpoint: run-key persistence              T1547.001    -> KP-0022
  6  App: JWT alg=none forged token             T1550.001    -> KP-0010
  7  App: IDOR payout enumeration               T1190        -> KP-0012
  8  App: SQLi on merchant search               T1190        -> KP-0011
  9  App: SSRF to cloud metadata                T1190        -> KP-0013
  10 Cloud: secrets access by assumed role      T1552.001    -> KP-0030
  11 Cloud: IAM privilege escalation            T1548        -> KP-0031
  12 Cloud: S3 made public (staging)            T1530        -> KP-0032
  13 App: bulk data export (exfil)              T1074        -> KP-0014
  14 App: BEC invoice bank-detail change        T1114        -> KP-0015
  15 App/LLM: prompt injection -> secret leak   T1552        -> KP-0016

Usage:
  python attack-scenarios/scattered-sable/run.py           # emit telemetry (default)
  python attack-scenarios/scattered-sable/run.py --live http://localhost:8080   # also hit the range
Then: python automation/normalize/normalize.py && python automation/detect/run_sigma.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "range", "kestrel-api"))
os.environ.setdefault("KESTREL_LOG_DIR", os.path.join(ROOT, "range", "data", "logs"))
from app import telemetry  # noqa: E402  (writes to the same app.jsonl the range uses)

ATTACKER_IP = "45.77.0.10"
VICTIM = "leo.kim"
TIMELINE = []  # (step, ts, technique, detection, note)
_T0 = datetime(2026, 8, 21, 13, 55, 0)
_clock = {"t": _T0}


def _ts(step_seconds: int) -> str:
    _clock["t"] = _clock["t"] + timedelta(seconds=step_seconds)
    return _clock["t"].strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def record(step, technique, detection, note):
    TIMELINE.append({"step": step, "ts": _clock["t"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "technique": technique, "detection": detection, "note": note})


def emit_chain():
    # 1) MFA fatigue: three denials in ~30s
    for i in range(3):
        telemetry.emit("user.mfa.push.deny", outcome="failure", actor=VICTIM, src_ip=ATTACKER_IP,
                       severity="medium", technique="T1621", ts_override=_ts(12),
                       reason="user_denied", city="Amsterdam", country="NL")
    record(1, "T1621", "KP-0001", "MFA push-bombing against leo.kim from NL")
    # override source so identity rules match (these are identity-tier events)
    _rewrite_source_last(3, "identity")

    # 2) coerced approval -> OAuth token grant (session theft)
    telemetry.emit("app.oauth.token.grant", outcome="success", actor=VICTIM, src_ip=ATTACKER_IP,
                   severity="high", technique="T1550.001", ts_override=_ts(20), country="NL")
    record(2, "T1550.001", "KP-0002", "OAuth token granted after coerced MFA approval")
    _rewrite_source_last(1, "identity")

    # 3-5) endpoint: encoded PowerShell, C2 beacon, persistence
    telemetry.emit("process_create", outcome="success", actor="KESTREL\\" + VICTIM,
                   src_ip="-", severity="high", technique="T1059.001", ts_override=_ts(30),
                   host="KP-LAPTOP-07", process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                   parent_process="C:\\Program Files\\Microsoft\\Teams\\current\\Teams.exe",
                   command_line="powershell -nop -w hidden -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0AA")
    record(3, "T1059.001", "KP-0020", "Encoded PowerShell stager via Teams lure")
    _rewrite_source_last(1, "sysmon")
    telemetry.emit("network_connect", outcome="success", actor="KESTREL\\" + VICTIM,
                   src_ip="45.77.0.10", severity="medium", technique="T1071", ts_override=_ts(6),
                   host="KP-LAPTOP-07", process="C:\\Windows\\System32\\rundll32.exe")
    record(4, "T1071", "KP-0021", "rundll32 beacon to sable-c2.example (45.77.0.10)")
    _rewrite_source_last(1, "sysmon")
    telemetry.emit("registry_set", outcome="success", actor="KESTREL\\" + VICTIM, src_ip="-",
                   severity="medium", technique="T1547.001", ts_override=_ts(40), host="KP-LAPTOP-07",
                   TargetObject="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater")
    record(5, "T1547.001", "KP-0022", "Run-key persistence 'Updater'")
    _rewrite_source_last(1, "sysmon")

    # 6-9) API abuse
    telemetry.emit("auth_alg_none_accepted", outcome="success", actor=VICTIM, src_ip=ATTACKER_IP,
                   severity="high", technique="T1550.001", ts_override=_ts(60), alg="none")
    record(6, "T1550.001", "KP-0010", "Forged JWT (alg=none) accepted")
    for i in range(8):  # IDOR enumeration
        telemetry.emit("object_access", action="read_payout", outcome="success", actor=VICTIM,
                       src_ip=ATTACKER_IP, object_type="payout", object_id=str(20 + i),
                       owner="2", severity="low", technique="T1190", ts_override=_ts(8),
                       authz="MISSING", amount_cents=999900)
    record(7, "T1190", "KP-0012", "Enumerated 8 payouts with missing object-level authz")
    telemetry.emit("db_query", action="search", outcome="success", actor=VICTIM, src_ip=ATTACKER_IP,
                   object_type="merchant", severity="high", technique="T1190", ts_override=_ts(15),
                   sqli_suspected=True, query="...WHERE name LIKE '%' UNION SELECT pan_token,brand,exp FROM cards--%'")
    record(8, "T1190", "KP-0011", "SQLi UNION to read tokenized cards")
    telemetry.emit("ssrf_fetch", outcome="success", actor=VICTIM, src_ip=ATTACKER_IP,
                   http_path="/fetch-logo", severity="critical", technique="T1190", ts_override=_ts(20),
                   target_url="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                   internal_target=True)
    record(9, "T1190", "KP-0013", "SSRF to IMDS to steal task-role creds")

    # 10-12) cloud
    telemetry.emit("GetSecretValue", outcome="success",
                   actor="arn:aws:sts::555:assumed-role/kestrel-api-task/session", src_ip=ATTACKER_IP,
                   severity="high", technique="T1552.001", ts_override=_ts(30),
                   request_json='{"secretId":"prod/payments/signing-key"}')
    record(10, "T1552.001", "KP-0030", "Read prod payment-signing secret via task role")
    _rewrite_source_last(1, "cloudtrail")
    telemetry.emit("AttachUserPolicy", outcome="success",
                   actor="arn:aws:sts::555:assumed-role/kestrel-api-task/session", src_ip=ATTACKER_IP,
                   severity="critical", technique="T1548", ts_override=_ts(25),
                   request_json='{"userName":"svc_payouts","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}')
    record(11, "T1548", "KP-0031", "Attached AdministratorAccess (privilege escalation)")
    _rewrite_source_last(1, "cloudtrail")
    telemetry.emit("PutBucketPolicy", outcome="success",
                   actor="arn:aws:sts::555:assumed-role/kestrel-api-task/session", src_ip=ATTACKER_IP,
                   severity="high", technique="T1530", ts_override=_ts(20),
                   request_json='{"bucketName":"kestrel-statements-prod","bucketPolicy":{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}}')
    record(12, "T1530", "KP-0032", "Made statements bucket public for staging/exfil")
    _rewrite_source_last(1, "cloudtrail")

    # 13-15) exfil + fraud + LLM
    telemetry.emit("bulk_export", outcome="success", actor=VICTIM, src_ip=ATTACKER_IP,
                   object_type="cards", severity="high", technique="T1074", ts_override=_ts(30),
                   record_count=80)
    record(13, "T1074", "KP-0014", "Bulk export of 80 tokenized card records")
    telemetry.emit("invoice_bank_change", outcome="success", actor=VICTIM, src_ip=ATTACKER_IP,
                   object_type="invoice", object_id="42", severity="high", technique="T1114",
                   ts_override=_ts(20), old_last4="1234", new_last4="9990")
    record(14, "T1114", "KP-0015", "Changed invoice #42 payout bank details (BEC)")
    telemetry.emit("copilot_system_prompt_leak", outcome="success", actor="merchant-user",
                   src_ip=ATTACKER_IP, session_id="sable-1", severity="critical", technique="T1552",
                   ts_override=_ts(15), data="system_prompt")
    record(15, "T1552", "KP-0016", "Prompt injection leaked copilot system prompt (key alias)")


# telemetry.emit doesn't accept ts_override/extra kwargs natively; patch lightly here.
_ORIG_EMIT = telemetry.emit
_LAST = {"lines": []}


def _emit_patched(event_type, **kw):
    ts_override = kw.pop("ts_override", None)
    ev = _ORIG_EMIT(event_type, **{k: v for k, v in kw.items() if k in _EMIT_KEYS or True})
    # rewrite ts in the just-written line for a coherent timeline
    if ts_override:
        _fix_last_field("ts", ts_override)
    return ev


_EMIT_KEYS = set()  # emit accepts **details, so everything passes through


def _fix_last_field(field, value):
    path = telemetry.LOG_FILE
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    if not lines:
        return
    obj = json.loads(lines[-1])
    obj[field] = value
    lines[-1] = json.dumps(obj, separators=(",", ":"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _rewrite_source_last(n, source):
    """Set 'source' on the last n emitted lines (so identity/sysmon/cloudtrail rules match)."""
    path = telemetry.LOG_FILE
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    for i in range(max(0, len(lines) - n), len(lines)):
        obj = json.loads(lines[i])
        obj["source"] = source
        lines[i] = json.dumps(obj, separators=(",", ":"))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", metavar="BASE_URL", help="also send benign requests to a running range")
    args = ap.parse_args()
    telemetry.emit = _emit_patched  # activate ts rewriting
    emit_chain()
    out = os.path.join(os.path.dirname(__file__), "timeline.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(TIMELINE, fh, indent=2)
    print(f"SCATTERED SABLE: emitted {len(TIMELINE)} attack steps -> {telemetry.LOG_FILE}")
    print(f"timeline -> {os.path.relpath(out, ROOT)}")
    if args.live:
        _run_live(args.live)
    print("next: python automation/normalize/normalize.py && python automation/detect/run_sigma.py")


def _run_live(base):
    import urllib.request
    try:
        urllib.request.urlopen(base + "/health", timeout=2)
        print(f"[live] range reachable at {base} (benign probes only)")
    except Exception as exc:
        print(f"[live] range not reachable ({exc}); telemetry-only mode still succeeded")


if __name__ == "__main__":
    main()
