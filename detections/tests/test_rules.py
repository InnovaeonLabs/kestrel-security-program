"""Detection unit tests — the 'tested detections' proof.

For every shipped Sigma rule we assert BOTH:
  * it FIRES on a crafted malicious event (true positive), and
  * it stays SILENT on a benign look-alike (no false positive).

This is what separates 'I wrote some rules' from 'I engineered tested detections'.
Run:  make test    (or)   .venv/Scripts/python -m pytest -q detections/tests
"""
from __future__ import annotations

import glob
import os
import sys

import pytest
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "automation", "detect"))
import run_sigma  # noqa: E402

RULES = {}
for _p in glob.glob(os.path.join(ROOT, "detections", "sigma", "*.yml")):
    with open(_p, encoding="utf-8") as _fh:
        _r = yaml.safe_load(_fh)
    RULES[_r["id"]] = _r


def ev(**over) -> dict:
    """Build one normalized event with sensible defaults, overridden per test."""
    base = {f: "-" for f in run_sigma.COLUMNS}
    base.update(http_status=0, details={}, ts="2026-08-21T14:00:00.000Z",
                event_id="t-" + str(over.get("_n", 0)))
    base.update({k: v for k, v in over.items() if k != "_n"})
    return base


def fires(rule_id, events) -> int:
    return len(run_sigma.run_rule_on_events(events, RULES[rule_id]))


# (rule_id, positive_events, negative_events)
CASES = [
    ("KP-0001",  # MFA fatigue (>=3 denials / 10m / actor)
     [ev(source="identity", event_type="user.mfa.push.deny", actor="leo", ts=f"2026-08-21T14:0{i}:00.000Z", _n=i) for i in range(3)],
     [ev(source="identity", event_type="user.mfa.push.deny", actor="leo", ts=f"2026-08-21T14:0{i}:00.000Z", _n=i) for i in range(2)]),
    ("KP-0002",
     [ev(source="identity", event_type="app.oauth.token.grant", technique="T1550.001", actor="leo")],
     [ev(source="identity", event_type="user.session.start", technique="T1078", actor="leo")]),
    ("KP-0010",
     [ev(source="kestrel-api", event_type="auth_alg_none_accepted", actor="attacker")],
     [ev(source="kestrel-api", event_type="login_success", actor="ava")]),
    ("KP-0011",
     [ev(source="kestrel-api", event_type="db_query", details={"sqli_suspected": True})],
     [ev(source="kestrel-api", event_type="db_query", details={"sqli_suspected": False})]),
    ("KP-0012",  # IDOR enumeration (>=5 / 5m / src_ip)
     [ev(source="kestrel-api", event_type="object_access", action="read_payout", src_ip="45.77.0.10",
         details={"authz": "MISSING"}, ts=f"2026-08-21T14:0{i}:00.000Z", _n=i) for i in range(5)],
     [ev(source="kestrel-api", event_type="object_access", action="read_payout", src_ip="203.0.113.10",
         details={"authz": "ok"}, ts=f"2026-08-21T14:0{i}:00.000Z", _n=i) for i in range(5)]),
    ("KP-0013",
     [ev(source="kestrel-api", event_type="ssrf_fetch", details={"internal_target": True})],
     [ev(source="kestrel-api", event_type="ssrf_fetch", details={"internal_target": False})]),
    ("KP-0014",
     [ev(source="kestrel-api", event_type="bulk_export", details={"record_count": 80})],
     [ev(source="kestrel-api", event_type="bulk_export", details={"record_count": 3})]),
    ("KP-0015",
     [ev(source="kestrel-api", event_type="invoice_bank_change", object_id="12")],
     [ev(source="kestrel-api", event_type="object_access", action="read_payout")]),
    ("KP-0016",
     [ev(source="kestrel-api", event_type="copilot_system_prompt_leak", session_id="s1")],
     [ev(source="kestrel-api", event_type="copilot_query", session_id="s1")]),
    ("KP-0020",
     [ev(source="sysmon", event_type="process_create", command_line="powershell -nop -w hidden -enc AAAA")],
     [ev(source="sysmon", event_type="process_create", command_line="powershell Get-Date")]),
    ("KP-0021",
     [ev(source="sysmon", event_type="network_connect", process="C:\\Windows\\System32\\rundll32.exe", src_ip="45.77.0.10")],
     [ev(source="sysmon", event_type="network_connect", process="C:\\Program Files\\Chrome\\chrome.exe", src_ip="1.1.1.1")]),
    ("KP-0022",
     [ev(source="sysmon", event_type="registry_set", details={"TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"})],
     [ev(source="sysmon", event_type="registry_set", details={"TargetObject": "HKCU\\Software\\Contoso\\Settings"})]),
    ("KP-0030",
     [ev(source="cloudtrail", event_type="GetSecretValue", actor="arn:aws:sts::555:assumed-role/kestrel-api-task/x")],
     [ev(source="cloudtrail", event_type="GetSecretValue", actor="arn:aws:iam::555:user/ava.reyes")]),
    ("KP-0031",
     [ev(source="cloudtrail", event_type="AttachUserPolicy", details={"request_json": '{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}'})],
     [ev(source="cloudtrail", event_type="AttachUserPolicy", details={"request_json": '{"policyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}'})]),
    ("KP-0032",
     [ev(source="cloudtrail", event_type="PutBucketPolicy", details={"request_json": '{"bucketPolicy":{"Statement":[{"Effect":"Allow","Principal":"*"}]}}'})],
     [ev(source="cloudtrail", event_type="PutBucketPolicy", details={"request_json": '{"bucketPolicy":{"Statement":[{"Effect":"Allow","Principal":"arn:aws:iam::555:root"}]}}'})]),
    ("KP-0040",
     [ev(source="email", event_type="email_url_click", details={"lookalike": True})],
     [ev(source="email", event_type="email_url_click", details={"lookalike": False})]),
    ("KP-0041",  # credential stuffing (>=10 failed logins / 5m / src_ip)
     [ev(source="kestrel-api", event_type="login_failure", src_ip="45.77.0.10",
         ts=f"2026-08-21T14:00:{i:02d}.000Z", _n=i) for i in range(10)],
     [ev(source="kestrel-api", event_type="login_failure", src_ip="203.0.113.10",
         ts=f"2026-08-21T14:00:{i:02d}.000Z", _n=i) for i in range(3)]),
    ("KP-0042",
     [ev(source="saas", event_type="mailbox.rule.create", details={"forward_external": True})],
     [ev(source="saas", event_type="mailbox.rule.create", details={"forward_external": False})]),
    ("KP-0050",  # off-hours bulk access (>=10 / 30m / actor)
     [ev(source="kestrel-api", event_type="object_access", actor="ivy", details={"off_hours": True},
         ts=f"2026-08-21T02:{i:02d}:00.000Z", _n=i) for i in range(10)],
     [ev(source="kestrel-api", event_type="object_access", actor="ivy", details={"off_hours": False},
         ts=f"2026-08-21T14:{i:02d}:00.000Z", _n=i) for i in range(10)]),
    ("KP-0051",
     [ev(source="kestrel-api", event_type="data_upload_external", details={"external": True})],
     [ev(source="kestrel-api", event_type="data_upload_external", details={"external": False})]),
    ("KP-0060",
     [ev(source="cicd", event_type="secret_scan_hit")],
     [ev(source="cicd", event_type="build_ok")]),
    ("KP-0061",
     [ev(source="cicd", event_type="dependency_vuln", details={"advisory_severity": "critical"})],
     [ev(source="cicd", event_type="dependency_vuln", details={"advisory_severity": "low"})]),
    ("KP-0062",
     [ev(source="cicd", event_type="deploy_prod", details={"signed": False})],
     [ev(source="cicd", event_type="deploy_prod", details={"signed": True})]),
]


@pytest.mark.parametrize("rule_id,pos,neg", CASES, ids=[c[0] for c in CASES])
def test_rule_true_positive(rule_id, pos, neg):
    assert fires(rule_id, pos) >= 1, f"{rule_id} ({RULES[rule_id]['title']}) failed to fire on malicious input"


@pytest.mark.parametrize("rule_id,pos,neg", CASES, ids=[c[0] for c in CASES])
def test_rule_no_false_positive(rule_id, pos, neg):
    assert fires(rule_id, neg) == 0, f"{rule_id} ({RULES[rule_id]['title']}) false-positived on benign input"


def test_every_rule_has_a_test():
    tested = {c[0] for c in CASES}
    missing = set(RULES) - tested
    assert not missing, f"rules without unit tests: {missing}"


def test_every_rule_has_attack_tag():
    for rid, r in RULES.items():
        assert any(str(t).lower().startswith("attack.t") for t in r.get("tags", [])), \
            f"{rid} missing an ATT&CK technique tag"
