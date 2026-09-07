# Threat Actor Profile — SCATTERED SABLE (fictional)

| | |
|---|---|
| **Aliases** | SABLE, "the payout crew" (lab-internal) |
| **Type** | Financially-motivated eCrime |
| **Sophistication** | Moderate; identity/social-engineering-led, living-off-the-land |
| **Targets** | Small high-value fintech/SaaS money-movers with lean security teams |
| **Objective** | Fraudulent payouts, data theft/extortion |

## TTPs (MITRE ATT&CK)
| Tactic | Technique | In our data |
|---|---|---|
| Initial Access | T1566 Phishing (lookalike link) | KP-0040 |
| Credential Access | T1621 MFA fatigue, T1110 cred stuffing, T1552 unsecured creds | KP-0001/0041/0016/0030 |
| Defense Evasion / Cred | T1550.001 forged/stolen tokens (alg=none) | KP-0002/0010 |
| Execution | T1059.001 encoded PowerShell | KP-0020 |
| Persistence | T1547.001 run key, T1114.003 mailbox rule | KP-0022/0042 |
| C2 | T1071 LOLBin beacon | KP-0021 |
| Priv-Esc | T1548 IAM AdministratorAccess | KP-0031 |
| Collection/Exfil | T1074 staging, T1530 public S3, T1114 BEC | KP-0014/0032/0015 |

## Why this actor drives our priorities
Identity + cloud + SaaS abuse over classic malware → our **P1 detections are identity/cloud/SaaS**, not endpoint AV.
This profile is the input to the detection-prioritization and the risk register (R-01, R-02, R-04).

## How intel changed our defense (lifecycle outcome)
- **Detection:** the actor's lookalike domain + C2 IP became feed indicators used to auto-enrich and prioritize alerts.
- **Hunting:** pivot on `45.77.0.10` and `sable@proton.example` across all sources.
- **Risk:** raised likelihood on R-01 (MFA fatigue) and R-07 (BEC) given this actor's known playbook.
