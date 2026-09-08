# DevSecOps Scan Results (real tool output)

These are **actual runs** of open-source security scanners against this repo — committed as evidence, not described
in the abstract. Reproduce any of them with the commands below.

| Tool | Type | Result | File |
|---|---|---|---|
| **gitleaks** 8.18.4 | Secret scan (git history) | **14 findings raw → 0 after allowlist** | `gitleaks-raw.json`, `gitleaks.json` |
| **detect-secrets** | Secret scan (entropy+keyword) | 3 decoys flagged | `detect-secrets.json` |
| **bandit** | Python SAST | 5 findings (SQLi, hardcoded secret, SSRF, …) | `bandit.txt` / `.json` |
| **pip-audit** | Dependency CVEs (SCA) | 7 (starlette) → **remediated to 0**; retest found+fixed 12 PyJWT | `pip-audit-app.txt`, `pip-audit-app-remediated.txt` |
| **pip-audit** | Dependency CVEs (demo) | 2 advisories (PyYAML 5.3.1) | `pip-audit-vuln-demo.txt` |
| **Checkov** | IaC misconfig | 41 fails + 1 secret | `../../evidence/logs/checkov-run.txt` |

## gitleaks — the before/after that matters
```bash
gitleaks detect --source . -c <default-only>      # RAW: 14 findings
gitleaks detect --source . -c .gitleaks.toml      # allowlisted: 0 (CI green)
```
Raw findings (default ruleset): `10 generic-api-key`, `3 jwt`, `1 hashicorp-tf-password`. The
`.gitleaks.toml` allowlist (which keeps the full default ruleset via `useDefault=true`) suppresses **only the
documented lab decoys**, so CI stays green **and a NEW, un-allowlisted secret would still fail the scan**. This is the
KP-0060 / SPLINTER VIPER supply-chain control, proven.

> **Lesson (real):** an earlier version committed a format-valid **fake AWS key** (`AKIA…`) as a decoy. Even fake, an `AKIA`-pattern key trips **GitHub's own push-protection** and would block a push — so it was **neutralized** (`AKIA-LAB-DECOY-NOT-A-REAL-KEY`) across history before publishing. The gitleaks demo still stands on the other decoys. Takeaway: never commit even a *fake* AWS-format key.

## bandit — SAST caught the intentional flaws
`bandit -r range/kestrel-api/app` →
- `B105 hardcoded_password_string` @ `auth.py` — the weak JWT secret (APP-2)
- `B608 hardcoded_sql_expressions` @ `main.py` — the SQL injection (APP-3)
- `B310 (urllib urlopen)` @ `main.py` — the SSRF sink (APP-4)
- `B113` (request timeout), `B311` (non-crypto random) — lower-signal

> Note: an earlier version of the code carried `# nosec-lab` comments that **accidentally suppressed bandit** (any
> `# nosec…` silences it). Renaming them to `# lab-intentional` restored real SAST output — a good reminder that
> suppression comments hide findings.

## pip-audit — a real remediation cycle (discover → fix → retest)
The pinned `fastapi==0.115.6` pulled a vulnerable transitive **starlette 0.41.3** (7 advisories). This was **remediated
and retested**:
1. Bump `fastapi 0.115.6 → 0.141.1` → starlette `0.41.3 → 1.6.0`. Re-scan: **starlette advisories cleared**, but the
   retest surfaced **12 PyJWT 2.10.1** advisories (fixed in 2.13.0) — exactly how iterative vuln-management works.
2. Bump `PyJWT 2.10.1 → 2.13.0`. Re-scan: **"No known vulnerabilities found"** (`pip-audit-app-remediated.txt`).
3. **56 unit tests still pass** on the upgraded stack — remediation without regression.

Findings VM-13 (starlette) and VM-14 (PyJWT) in the register are now **Remediated-Retested**.

## What did NOT run here (honest)
- **Semgrep** — its Windows binary support is unreliable; **bandit** is the Python-native SAST substitute that ran for
  real, and Semgrep runs cleanly in the Linux CI (`.github/workflows/ci.yml`).
- **Trivy** — needs a multi-hundred-MB vuln-DB download (and ideally Docker, which was offline on the lab host);
  **pip-audit** provides the dependency-CVE coverage locally. Trivy runs in the Linux CI for container/filesystem scans.

## Reproduce
```bash
pip install bandit pip-audit detect-secrets
bandit -r range/kestrel-api/app -f txt
pip-audit -r range/kestrel-api/requirements.txt
detect-secrets scan range/kestrel-api cloud-security docker-compose.yml
# gitleaks: download the binary, then `gitleaks detect --source . -c .gitleaks.toml`
```
