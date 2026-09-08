# DevSecOps & Software Supply Chain (Phase 11/12)

Security checks that run in CI to catch issues **before deploy**: secrets, SAST, IaC, and dependency scanning.
Workflow: [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## Pipeline design (honest framing)
This repo intentionally contains a **vulnerable app + misconfigured IaC + labelled lab secrets** as the *target*, so the
scanners are meant to **find** things. Therefore:
- **Gating job — `tests`:** builds telemetry, runs detections, and runs the unit tests (`detections/tests` +
  `appsec/tests`). This must pass. It's the detection-as-code + remediation regression gate.
- **Report-only jobs — `secret-scan` (gitleaks), `sast` (Semgrep), `iac-scan` (Checkov), `deps` (pip-audit):** surface
  the planted issues as findings/artifacts. In a real product repo these would gate; here they demonstrate coverage.

## What each catches (REAL scanner output committed → `scan-results/`)
| Check | Tool | Finds |
|---|---|---|
| Secrets | gitleaks | **14 raw → 0 after allowlist** (`scan-results/gitleaks-raw.json`); detect-secrets found 3 |
| SAST | bandit (Semgrep in CI) | **5 findings** incl. SQLi/hardcoded-secret/SSRF (`scan-results/bandit.txt`) |
| IaC | Checkov | **41 misconfigs + 1 secret** (`../evidence/logs/checkov-run.txt`) |
| Dependencies | pip-audit | **7 CVEs** in app deps (starlette); demo pin +2 (`scan-results/pip-audit-app.txt`) |

## Supply-chain lesson
The `.gitleaks.toml` allowlist covers only the **documented** decoys — a **new** committed secret is still caught and
would fail review. This is the SCATTERED SABLE supply-chain link (T1195): one leaked key or poisoned dependency reaches
all 300 customer platforms, so the cheapest place to stop it is the PR.

## Enterprise equivalent
Add signed commits + protected branches + required reviews, SBOM generation (Syft) + provenance (SLSA), Trivy for
container image scanning, and least-privilege OIDC deploy roles (no long-lived cloud keys).
