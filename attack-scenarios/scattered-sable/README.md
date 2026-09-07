# Attack Scenario — SCATTERED SABLE (Phase 8)

A single, coherent, **financially-motivated** intrusion against Kestrel Pay, emulated benignly. It exercises the full
kill chain from identity compromise to attempted fraud, and every step maps to a **tested detection**. Running it makes
all 18 detections fire (App/API + LLM rules included), which feeds the incident in [`../../incident-response/`](../../incident-response/).

## Safety / scope
No real exploitation, no third party, no malware. `run.py` emits the *same normalized telemetry a live attack would*
(and, with `--live <url>`, sends only benign probes to your own range). Fully reversible: delete `range/data/` and reseed.

## Run
```bash
make emulate SCENARIO=scattered-sable      # emit the chain -> range/data/logs/app.jsonl + timeline.json
make detect                                 # -> 25 alerts / 18 rules / 12 techniques
python automation/report/metrics.py         # -> metrics/metrics.json
```

## The chain — ATTACK → ASSET → TELEMETRY → DETECTION → RESPONSE → REMEDIATION → RETEST
| # | Attack step | ATT&CK | Asset affected | Telemetry (source) | Detection | Response | Remediation | Retest |
|---|---|---|---|---|---|---|---|---|
| 1 | MFA push-bombing | T1621 | Identity (AST-007) | Okta deny burst (identity) | KP-0001 | Disable sessions, reset MFA | Phishing-resistant FIDO2 + number-matching | KESTREL_HARDENED copilot/authz + IdP policy |
| 2 | Coerced approval → token theft | T1550.001 | Identity/session | OAuth grant (identity) | KP-0002 | Revoke tokens | Conditional access, short token TTL | rule re-run silent post-fix |
| 3 | Encoded PowerShell stager | T1059.001 | Endpoint (AST-012) | Sysmon EID1 (endpoint) | KP-0020 | Isolate host | App-control / constrained language mode | Sysmon replay |
| 4 | LOLBin C2 beacon | T1071 | Endpoint/network | Sysmon EID3 (endpoint) | KP-0021 | Block C2 IP/domain | Egress filtering, EDR | replay |
| 5 | Run-key persistence | T1547.001 | Endpoint | Sysmon EID13 (endpoint) | KP-0022 | Remove key, re-image | Least-admin, monitored autoruns | replay |
| 6 | Forged JWT (alg=none) | T1550.001 | API (AST-004) | auth_alg_none (app) | KP-0010 | Rotate signing secret | Pin alg=HS256, env secret | `KESTREL_HARDENED=1` |
| 7 | IDOR payout enumeration | T1190 | Ledger (AST-003) | object_access authz=MISSING (app) | KP-0012 | Rate-limit, block token | Object-level authz | hardened build |
| 8 | SQLi on merchant search | T1190 | Ledger/cards | db_query sqli (app) | KP-0011 | WAF block | Parameterized queries | hardened build |
| 9 | SSRF → cloud metadata | T1190 | Cloud creds (AST-002) | ssrf_fetch internal (app) | KP-0013 | Rotate role creds | URL allow-list, IMDSv2 | hardened build |
| 10 | Secrets access by role | T1552.001 | Signing key (AST-001) | GetSecretValue (cloudtrail) | KP-0030 | Rotate key, scope role | Least-priv role, secret alerting | CloudTrail replay |
| 11 | IAM privilege escalation | T1548 | AWS account (AST-002) | AttachUserPolicy (cloudtrail) | KP-0031 | Detach policy, quarantine | SCP guardrails, deny iam:Attach* | replay |
| 12 | S3 made public | T1530 | S3 (AST-010) | PutBucketPolicy (cloudtrail) | KP-0032 | Revert policy | Block Public Access org-wide | Checkov + replay |
| 13 | Bulk data export | T1074 | Customer data (AST-009) | bulk_export (app) | KP-0014 | Block, preserve evidence | Export dual-control + DLP | hardened build |
| 14 | BEC invoice bank change | T1114 | Invoices | invoice_bank_change (app) | KP-0015 | Freeze payout, verify | Out-of-band verification | hardened build |
| 15 | Prompt injection → key leak | T1552 | LLM copilot (AST-019) | copilot_leak (app) | KP-0016 | Kill session, rotate | Input/output guards, tool scoping | `KESTREL_HARDENED=1` |

## Measured result (computed by `automation/report/metrics.py` — see [`../../metrics/metrics.json`](../../metrics/metrics.json))
- **Chain detection coverage: 100%** (16/16 techniques, 18/18 steps) — for *this emulated chain* (broader ATT&CK gaps are documented in [`../../detections/coverage/`](../../detections/coverage/)).
- **25 alerts**, **15/18 rules fired**, **0 false positives** on the 40-event benign baseline.
- **Detection-opportunity window ≈ 6 min** between first detectable step (MFA fatigue) and first business-impact action (exfil/BEC) — the window where an analyst contains the intrusion.
