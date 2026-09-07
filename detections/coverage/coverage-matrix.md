# ATT&CK Coverage Matrix (generated)

> Auto-generated from `detections/sigma/*.yml` by `automation/detect/coverage.py`. All rules ship with unit tests (`detections/tests`). Coverage is deliberately partial — gaps are listed so they can be closed in the purple-team phase.

| ATT&CK | Detection | ID | Data source | Severity | Tested |
|---|---|---|---|---|---|
| `T1114` | Invoice Bank-Detail Change (BEC Indicator) | KP-0015 | App/API | medium | ✅ unit |
| `T1074` | Bulk Customer Data Export | KP-0014 | App/API | high | ✅ unit |
| `T1190` | IDOR - Payout Object Enumeration | KP-0012 | App/API | high | ✅ unit |
| `T1550.001` | JWT alg=none Accepted (Auth Bypass) | KP-0010 | App/API | high | ✅ unit |
| `T1190` | SQL Injection Indicators in Merchant Search | KP-0011 | App/API | high | ✅ unit |
| `T1190` | SSRF to Internal / Cloud Metadata | KP-0013 | App/API | critical | ✅ unit |
| `T1548` | IAM Privilege Escalation - AdministratorAccess Attached | KP-0031 | Cloud/CloudTrail | critical | ✅ unit |
| `T1530` | S3 Bucket Policy Made Public | KP-0032 | Cloud/CloudTrail | high | ✅ unit |
| `T1552.001` | Secrets Manager Access by Assumed Role | KP-0030 | Cloud/CloudTrail | high | ✅ unit |
| `T1566` | Phishing Link Click to Lookalike Domain | KP-0040 | - | high | ✅ unit |
| `T1059.001` | Encoded / Hidden PowerShell Execution | KP-0020 | Endpoint/Sysmon | high | ✅ unit |
| `T1071` | LOLBin Making Network Connection | KP-0021 | Endpoint/Sysmon | medium | ✅ unit |
| `T1547.001` | Registry Run Key Persistence | KP-0022 | Endpoint/Sysmon | medium | ✅ unit |
| `T1110` | Credential Stuffing / Brute Force | KP-0041 | App/API | medium | ✅ unit |
| `T1621` | MFA Fatigue - Repeated Push Denials | KP-0001 | Identity | high | ✅ unit |
| `T1550.001` | OAuth Token Grant Following MFA Fatigue | KP-0002 | Identity | medium | ✅ unit |
| `T1059` | LLM Prompt Injection / Insecure Tool Use (Support Copilot) | KP-0016 | App/API | high | ✅ unit |
| `T1552` | LLM Prompt Injection / Insecure Tool Use (Support Copilot) | KP-0016 | App/API | high | ✅ unit |
| `T1114.003` | Mailbox Forwarding Rule to External Address | KP-0042 | - | high | ✅ unit |

## Documented coverage gaps (honest)

| ATT&CK | Gap |
|---|---|
| `T1195` | Supply-chain compromise — handled by CI gates (gitleaks/Semgrep/Checkov/pip-audit), not runtime detection |
| `T1078.004` | Valid cloud accounts (broad) — partially covered via KP-0030/31; full coverage needs richer CloudTrail baseline |

**Techniques with a tested detection:** 16 — T1059, T1059.001, T1071, T1074, T1110, T1114, T1114.003, T1190, T1530, T1547.001, T1548, T1550.001, T1552, T1552.001, T1566, T1621
