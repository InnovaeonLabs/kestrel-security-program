# SPLINTER VIPER — Software Supply-Chain / CI-CD Compromise

The attacker never touches production directly — they **poison the pipeline**. This is where the DevSecOps CI gates
earn their keep, and it exercises a dedicated `cicd` telemetry source.

## Scope / safety
Benign emulation — emits `cicd` telemetry only. `make emulate SCENARIO=supply-chain-viper`.

## Chain — ATTACK → ASSET → TELEMETRY → DETECTION → RESPONSE
| # | Step | ATT&CK | Asset | Telemetry | Detection | Response |
|---|---|---|---|---|---|---|
| 1 | Secret committed / found in CI | T1552 | Secrets (AST-011), CI (AST-005) | secret_scan_hit (gitleaks) | **KP-0060** | Revoke/rotate key; block merge |
| 2 | Malicious dependency added | T1195.002 | Dependencies (AST-018) | dependency_vuln (critical) | **KP-0061** | Fail build; pin/replace dep; SBOM diff |
| 3 | Unsigned build → production | T1195 / T1554 | CI/CD, prod (AST-005/004) | deploy_prod `signed=false` | **KP-0062** | Block deploy; require signed builds |

## Detection idea (why it works)
These are **pre-deploy** signals on a `cicd` source, so the cheapest place to stop a supply-chain attack is the PR/build
— one leaked key or poisoned dependency would otherwise reach all 300 customer platforms. Ties directly to the CI
workflow ([`../../.github/workflows/ci.yml`](../../.github/workflows/ci.yml)) which runs gitleaks/Semgrep/Trivy/Checkov.

## Result
KP-0060 + KP-0061 + KP-0062 fire; **0** false positives on the benign baseline. Maps to risk **R-05** (supply-chain).
Enterprise equivalent: signed commits, SLSA provenance, Syft SBOM, Trivy image scans, least-privilege OIDC deploy.
