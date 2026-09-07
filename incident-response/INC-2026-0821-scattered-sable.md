# Incident Report — INC-2026-0821 "SCATTERED SABLE"

| | |
|---|---|
| **Incident ID** | INC-2026-0821 |
| **Severity** | SEV-1 (crown-jewel access + attempted fraud) |
| **Status** | Contained → Eradicated → Recovered (lab exercise) |
| **Detected** | 2026-08-21 (identity anomaly, KP-0001) |
| **Classification** | Financially-motivated intrusion (eCrime); identity-led, cloud + API impact |
| **Handler** | Security (project author) |
| **Data source of record** | `range/data/telemetry/telemetry.duckdb`; alerts in `../evidence/alerts/alerts.jsonl` |

## 1. Executive summary (1 paragraph)
An external actor compromised an engineer's identity via MFA push-bombing, stole a session token, established endpoint
persistence and C2, then pivoted through the payments API (forged JWT, IDOR, SQLi, SSRF) into the AWS account, where it
read the production payment-signing secret, escalated IAM to AdministratorAccess, exposed an S3 bucket, and attempted
data exfiltration and invoice fraud. **The intrusion was detectable at initial access — ~7 minutes before the first
fraud action** — by shipped detections. All 18 detections fired (25 alerts, 16 ATT&CK techniques). See the business
brief in [`exec-summary.md`](exec-summary.md).

## 2. Timeline (from `attack-scenarios/scattered-sable/timeline.json`)
| Time (UTC) | Event | ATT&CK | Alert |
|---|---|---|---|
| 13:55 | MFA push-bombing vs leo.kim from NL IP 45.77.0.10 | T1621 | KP-0001 |
| 13:56 | Coerced MFA approval → OAuth token grant | T1550.001 | KP-0002 |
| 13:57 | Encoded PowerShell stager on KP-LAPTOP-07 (Teams lure) | T1059.001 | KP-0020 |
| 13:57 | rundll32 C2 beacon → 45.77.0.10 | T1071 | KP-0021 |
| 13:58 | Run-key persistence "Updater" | T1547.001 | KP-0022 |
| 13:59 | Forged JWT (alg=none) accepted by API | T1550.001 | KP-0010 |
| 14:00 | IDOR enumeration of 8 payouts (authz missing) | T1190 | KP-0012 |
| 14:00 | SQLi UNION to read tokenized cards | T1190 | KP-0011 |
| 14:01 | SSRF to IMDS → task-role creds | T1190 | KP-0013 |
| 14:01 | GetSecretValue on prod/payments/signing-key | T1552.001 | KP-0030 |
| 14:02 | AttachUserPolicy AdministratorAccess (priv-esc) | T1548 | KP-0031 |
| 14:02 | PutBucketPolicy → statements bucket public | T1530 | KP-0032 |
| 14:03 | Bulk export of 80 card records | T1074 | KP-0014 |
| 14:03 | Invoice #42 payout bank details changed (BEC) | T1114 | KP-0015 |
| 14:03 | Prompt injection leaked copilot system prompt | T1552 | KP-0016 |

## 3. Triage
- **First alert:** KP-0001 (MFA fatigue) — actor `leo.kim`, source IP `45.77.0.10` (NL), 3 denials in <40s.
- **Correlation:** same actor + IP appears in OAuth grant (KP-0002), then endpoint host `KP-LAPTOP-07` beacons to the
  same IP → single-actor intrusion, not noise. Enrichment pivots on IP `45.77.0.10` and actor `leo.kim`.
- **Severity call:** raised to SEV-1 when cloud secrets access (KP-0030) + IAM priv-esc (KP-0031) fired — crown-jewel exposure.

## 4. Evidence collected (DFIR)
See [`../dfir/investigation-notes.md`](../dfir/investigation-notes.md). Preserved: normalized telemetry
(`events.jsonl`), the DuckDB store, alert set, endpoint indicators (encoded PS command line, run-key value, C2 IP/domain),
cloud indicators (assumed-role session, secretId, policy ARN, bucket name). IOCs extracted to
[`../dfir/iocs.csv`](../dfir/iocs.csv).

## 5. Scope & impact
| Crown jewel | Exposure |
|---|---|
| Payment-signing secret (AST-001) | **Read** by assumed role → assume compromised → rotate |
| Prod AWS account/IAM (AST-002) | Priv-esc to admin → account-wide exposure |
| Ledger / cardholder data (AST-003/009) | 80 tokenized records exported; card data queried via SQLi |
| Identity (AST-007) | 1 engineer identity + session compromised |
| Invoices | 1 fraudulent bank-detail change (payout not yet released) |

## 6. Containment → Eradication → Recovery
- **Contain:** disable `leo.kim` sessions + revoke tokens; isolate KP-LAPTOP-07; block `45.77.0.10` / `sable-c2.example`;
  detach the AdministratorAccess policy; revert the S3 bucket policy; freeze invoice #42 payout.
- **Eradicate:** remove run-key persistence; re-image endpoint; **rotate the payment-signing key** and all secrets the
  role could read; rotate the JWT signing secret; review IAM for other backdoors.
- **Recover:** restore least-privilege role; re-enable identity with FIDO2; verify invoice bank details out-of-band;
  confirm detections green on replay. Recovery priorities and RTO in [`../resilience/`](../resilience/).

## 7. Root-cause analysis (5 whys, abbreviated)
Fraud attempt → API/cloud let a single stolen identity reach money → **identity had no phishing-resistant MFA and
cloud roles were over-privileged with no guardrails** → the org treated identity as an afterthought and cloud IAM as
set-and-forget. **Root cause: identity + cloud-IAM were not treated as the primary perimeter.** (Maps to risks R-01,
R-02, R-04 in `../docs/risk/risk-register.csv`.)

## 8. Lessons learned → improvements (feeds purple team)
1. Phishing-resistant MFA + number-matching (kills KP-0001 root cause).
2. Least-privilege cloud roles + SCP guardrails + secret-access alerting (R-02/R-04).
3. Ship the `KESTREL_HARDENED=1` API fixes (authz, alg-pinning, parameterized queries, SSRF allow-list, copilot guards).
4. Add the two coverage gaps as detections: brute-force/credential-stuffing (T1110), email-rule creation (T1114.003).
Full before/after in [`../purple-team/scattered-sable-purpleteam.md`](../purple-team/scattered-sable-purpleteam.md).
