# Technical Security Assessment — Project KESTREL

## Scope & method
Full-lifecycle assessment of the Kestrel Pay lab: threat model → telemetry → detection engineering → adversary
emulation → IR/DFIR → remediation → measurement. All artifacts are in-repo and reproducible (`make`).

## Findings summary
- **12 vulnerabilities** (8 P1) across API, cloud/IaC, identity, and data — `vulnerability-management/register.csv`.
- **41 IaC misconfigurations + 1 hardcoded secret** — Checkov, `evidence/logs/checkov-run.txt`.
- **7 attack paths** from a phished engineer to crown jewels — `identity/graph/attack-paths.md`.

## Controls built & validated
| Domain | Control | Validation |
|---|---|---|
| Detection | 15 Sigma rules + Sigma→DuckDB runner | 32 unit tests pass; 22 alerts on emulation; 0 FP baseline |
| Threat-informed defense | ATT&CK coverage matrix + Navigator | generated from rules; gaps documented |
| Cloud/IAM | least-priv roles, SCP, S3 BPA, rotation | Checkov re-scan; attack-paths 7→0 |
| AppSec | authz, alg-pinning, paramz queries, SSRF allow-list, copilot guards | `appsec/tests` (4 pass) |
| DevSecOps | gitleaks/Semgrep/Checkov/pip-audit in CI | `.github/workflows/ci.yml` |
| Vuln mgmt | risk-based lifecycle | register with retest evidence |

## Detection engineering detail
Rules authored in Sigma, compiled to DuckDB SQL by `automation/detect/run_sigma.py` (supports contains/startswith/
endswith/regex/numeric modifiers, boolean conditions, and a temporal-aggregation extension for velocity rules). Each
rule is documented (threat, data source, logic, ATT&CK, false positives, validation, severity, response) and unit-tested.

## Emulation → detection mapping
SCATTERED SABLE (15 steps) → 12 ATT&CK techniques → 15 detections → 22 alerts. Full table in
`attack-scenarios/scattered-sable/README.md`. App/API/LLM rules are silent on the benign baseline (0 FP) and fire under attack.

## Gaps & limitations (honest)
- Batch (not streaming) detection; single-node telemetry; cloud analyzed via CloudTrail sample + policy-sim.
- Coverage gaps: T1566, T1110, T1114.003, T1195 (documented in `detections/coverage/`).
- Enterprise equivalents documented throughout (`docs/architecture/lab-vs-enterprise.md`).

## Recommendations (prioritized)
1. Roll out FIDO2 + conditional access (closes R-01 root cause).
2. Ship the hardened API build + scoped IAM/SCP to production.
3. Close the two detection gaps; add streaming + EDR at scale.
