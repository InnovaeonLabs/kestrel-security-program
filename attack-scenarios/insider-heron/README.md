# HOLLOW HERON — Insider Data Theft

A **different threat model** from the flagship: no external compromise. A trusted internal user abuses *legitimate*
access to steal customer data. This is the case volume-blind, external-IP-based detections miss.

## Scope / safety
Benign emulation — emits telemetry only (no real data leaves anywhere). `make emulate SCENARIO=insider-heron`.

## Chain — ATTACK → ASSET → TELEMETRY → DETECTION → RESPONSE
| # | Step | ATT&CK | Asset | Telemetry | Detection | Response |
|---|---|---|---|---|---|---|
| 1 | Off-hours login (legit creds) | T1078 | Identity (AST-007) | login_success `off_hours` | context | Review session; step-up auth off-hours |
| 2 | Bulk read of customer records | T1074 | Customer/card data (AST-009/003) | 15× object_access `off_hours` | **KP-0050** | Alert; suspend account pending review |
| 3 | Mass export | T1074 | Card data | bulk_export (120 recs) | **KP-0014** | Block export; preserve evidence |
| 4 | Exfil to personal cloud | T1567.002 | Customer data | data_upload_external → `personal-dropbox.example` | **KP-0051** | Block egress; HR/legal; DLP |

## Detection idea (why it works)
The insider has valid credentials and a valid office IP, so IP/auth-based rules stay quiet. **KP-0050** keys on
**volume + timing** (≥10 record reads off-hours by one actor); **KP-0051** keys on the **destination** (upload to a
non-corporate cloud). Together they catch trust abuse that SABLE-style rules miss.

## Result
KP-0050 + KP-0014 + KP-0051 fire; **0** false positives on the benign baseline. Enterprise equivalent: UEBA + DLP +
egress proxy logs. Maps to risk **R-10** (insider bulk export).
