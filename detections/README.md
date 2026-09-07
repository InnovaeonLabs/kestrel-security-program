# Detection Engineering (Phase 7) — Detection-as-Code

Custom, **unit-tested** detections written as portable **Sigma** YAML, compiled to DuckDB SQL and run over the
normalized telemetry. This is the spine of the whole project.

## What ships
- **15 rules** in [`sigma/`](sigma/) across Identity, App/API, Endpoint, Cloud, and LLM.
- A **compiler/runner** ([`../automation/detect/run_sigma.py`](../automation/detect/run_sigma.py)) — a purpose-built
  Sigma-subset engine (+ temporal/threshold aggregation) so it stays dependency-light on an 8 GB host.
- **32 passing unit tests** ([`tests/`](tests/)) — every rule is asserted to **fire on malicious input** and stay
  **silent on benign** input. Evidence: [`../evidence/alerts/pytest-detections.txt`](../evidence/alerts/pytest-detections.txt).
- An auto-generated **ATT&CK coverage matrix** + **Navigator layer** ([`coverage/`](coverage/)) — 13 techniques
  covered, with **documented gaps** (nothing hidden).

## Run
```bash
make detect     # normalize -> run all rules -> evidence/alerts/alerts.jsonl
make test       # pytest: 32 tests, fires-on-malicious + silent-on-benign
python automation/detect/coverage.py   # regenerate the coverage matrix + Navigator layer
```
Current result on baseline+scenario telemetry: **8 alerts / 8 techniques** fire (identity, endpoint, cloud). The
App/API + LLM rules are intentionally **silent on the benign baseline** (zero false positives) and fire once the API is
attacked in the Phase 8 emulation — proven now by their unit tests.

## Rule catalogue
| ID | Title | Source | ATT&CK | Level |
|---|---|---|---|---|
| KP-0001 | MFA Fatigue – Repeated Push Denials | Identity | T1621 | high |
| KP-0002 | OAuth Token Grant Following MFA Fatigue | Identity | T1550.001 | medium |
| KP-0010 | JWT alg=none Accepted (Auth Bypass) | App/API | T1550.001 | high |
| KP-0011 | SQL Injection Indicators | App/API | T1190 | high |
| KP-0012 | IDOR – Payout Object Enumeration | App/API | T1190 | high |
| KP-0013 | SSRF to Internal / Cloud Metadata | App/API | T1190 | critical |
| KP-0014 | Bulk Customer Data Export | App/API | T1074 | high |
| KP-0015 | Invoice Bank-Detail Change (BEC) | App/API | T1114 | medium |
| KP-0016 | LLM Prompt Injection / Insecure Tool Use | App/LLM | T1059, T1552 | high |
| KP-0020 | Encoded / Hidden PowerShell | Endpoint | T1059.001 | high |
| KP-0021 | LOLBin Making Network Connection | Endpoint | T1071 | medium |
| KP-0022 | Registry Run Key Persistence | Endpoint | T1547.001 | medium |
| KP-0030 | Secrets Manager Access by Assumed Role | Cloud | T1552.001 | high |
| KP-0031 | IAM Privilege Escalation (AdministratorAccess) | Cloud | T1548 | critical |
| KP-0032 | S3 Bucket Policy Made Public | Cloud | T1530 | high |

## Detection documentation template
Each rule's YAML carries the fields a real detection engineer expects, and the story for each is:

| Field | Where |
|---|---|
| Threat / use case | `description` |
| Data source | `logsource` → normalized `source` |
| Detection logic | `detection.selection` + `condition` (+ `aggregation` for velocity/threshold) |
| ATT&CK technique | `tags: attack.tXXXX` |
| Expected benign behavior / false positives | `falsepositives` |
| Validation procedure | `detections/tests/test_rules.py` (true-positive + no-false-positive) |
| Severity | `level` |
| Response action | scenario runbooks in `../attack-scenarios/` + `../incident-response/` |

**Enterprise equivalent:** author in Sigma → convert with `sigma-cli` to your SIEM (Splunk SPL / Elastic EQL /
Sentinel KQL) in CI, deploy via a detection-as-code repo with the same unit tests. Here the backend is DuckDB; the
authoring format and the test discipline are identical.
