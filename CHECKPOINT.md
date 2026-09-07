# PROJECT KESTREL — Build Checkpoint / State Tracker

> This file is the single source of truth for "where are we." Update the status column at the end of every phase.
> If work resumes in a new session, read this file first — it lets execution continue without re-designing anything.

**Project:** Kestrel Pay Security Program (repo codename *Project KESTREL*)
**Host constraints (design driver):** Intel i5-6300U · 2 cores / 4 threads · 8 GB RAM · ~67 GB free · Docker+WSL2 · Python 3.13 · Node 25 · Windows 11
**Architecture stance:** SIEM-less / detection-as-code / telemetry-as-data. Light Docker (one profile at a time) + Python + real Windows-host telemetry. No always-on Elastic. No multi-VM.
**Last updated:** 2026-09-06

---

## Phase status

| # | Phase | Status | Key artifacts (path) |
|---|-------|--------|----------------------|
| 0 | Executive project definition | ✅ DONE | `docs/00-project-charter.md`, `README.md`, this file |
| 1 | Business & asset modeling | ✅ DONE | `docs/architecture/company-profile.md`, `assets/asset-inventory.csv`, `docs/threat-model/threat-model.md`, `docs/risk/risk-register.csv` |
| 2 | Architecture & lab deployment | ✅ DONE | `range/kestrel-api/` (FastAPI vuln app + LLM copilot), `docker-compose.yml`, `docs/architecture/lab-vs-enterprise.md`, `docs/architecture/current-state.md` |
| 3 | Logging / telemetry foundation | ✅ DONE | `automation/normalize/normalize.py` (→DuckDB), `config/sysmon/`, `scripts/export-windows-telemetry.ps1` |
| 4 | Baseline security controls | ✅ DONE | `config/sysmon/`, nginx rate-limit, `KESTREL_HARDENED` toggle, hardened.tf.example |
| 5 | Vulnerability & exposure assessment | ✅ DONE | `vulnerability-management/register.csv` (12 findings, risk-based) + README |
| 6 | App / API / Cloud / Identity security | ✅ DONE | `appsec/` (8 findings, 4 retest pass), `cloud-security/` (Checkov 41), `identity/graph/` (7→0) |
| 7 | Detection engineering | ✅ DONE | `detections/sigma/` (18 rules), `automation/detect/run_sigma.py`, `detections/tests/` (42 pass), `detections/coverage/` |
| 8 | Controlled adversary simulation | ✅ DONE | `attack-scenarios/scattered-sable/run.py` (18-step chain), `timeline.json` |
| 9 | Incident response & DFIR | ✅ DONE | `incident-response/INC-2026-0821-*.md` + `exec-summary.md`, `dfir/investigation-notes.md` + `iocs.csv` |
| 10 | Purple-team improvement | ✅ DONE | `purple-team/scattered-sable-purpleteam.md` (before/after measured) |
| 11 | Automation | ✅ DONE | `automation/normalize` + `detect` + `report/metrics.py` + `report/build_report.py`; (future: SOAR playbook) |
| 12 | GRC / risk / architecture review | ✅ DONE | `docs/risk/control-mapping.md` (NIST CSF 2.0/CIS v8/SOC 2), `docs/architecture/target-state.md` |
| 13 | Resilience & recovery | ✅ DONE | `resilience/README.md` (RTO/RPO, golden IaC, monitoring recovery) |
| 14 | Measurement & posture comparison | ✅ DONE | `metrics/metrics.json` (computed), `dashboard/index.html` (generated) |
| 15 | Portfolio / GitHub packaging | ✅ DONE | `README.md` (progressive disclosure, real numbers), `reports/` assessments, CI |
| 16 | Resume / LinkedIn / interview prep | ✅ DONE | `reports/career/` (resume bullets, LinkedIn, interview prep) |

## Decisions log (why we did it this way)
- **D-001** Rejected multi-VM SOC (GOAD/Security Onion): won't fit 8 GB/2-core. Chose SIEM-less detection-as-code. *Tradeoff documented in `docs/architecture/lab-vs-enterprise.md` (Phase 2).*
- **D-002** Analytics = DuckDB + Sigma-compiled-to-SQL instead of Elastic (RAM). Static HTML dashboard instead of always-on Kibana.
- **D-003** Endpoint telemetry from the real Windows host via Sysmon + PowerShell logging (no Windows VM).
- **D-004** Cloud = Terraform + Checkov (static) + CloudTrail sample + Python policy-sim, not a running cloud; LocalStack optional if RAM allows.
- **D-005** Emulated adversary "SCATTERED SABLE" = fictional financially-motivated eCrime actor (Scattered-Spider-flavored identity/cloud/SaaS TTPs) to showcase modern fintech-relevant + high-differentiation domains.

## Status: ALL 16 PHASES COMPLETE (v1). Ready to push to GitHub.
- Full pipeline reproduces: `make emulate && make detect && python automation/report/metrics.py && make report`.
- `make test` (detections) + `pytest appsec/tests` (hardening) all pass (42 tests total).
- **Optional future polish (v2):** SOAR-style triage/enrichment playbook + analyst-minutes-saved metric; a live
  LocalStack cloud scenario; close ATT&CK gaps T1566/T1110/T1114.003; add screen-capture GIFs of detections firing.
- **Before pushing:** create empty GitHub repo, then `git branch -M main && git remote add origin <url> && git push -u origin main`.
  CI (`.github/workflows/ci.yml`) runs on first push; lab decoys are allowlisted in `.gitleaks.toml`.

## Metrics (computed from real evidence — metrics/metrics.json)
| Metric | Baseline | Post-improvement | Source of truth |
|---|---|---|---|
| ATT&CK chain detection coverage | 0% | **100% (16/16)** | `metrics/metrics.json` |
| Attack steps detected | 0/18 | **18/18** | `metrics/metrics.json` |
| Alerts on the intrusion | 0 | **25** | `evidence/alerts/alerts.jsonl` |
| FP rate on benign baseline | n/a | **0 / 40** | `evidence/alerts/detection-run.txt` |
| Detection-opportunity window before impact | none | **~7.2 min** | `metrics/metrics.json` |
| Detection unit tests | 0 | **42 pass** | `evidence/alerts/pytest-detections.txt` |
| Critical/High app flaws remediated + retested | 0 | **2 (JWT, prompt-injection) + 6 by rule** | `appsec/tests` (4 pass) |
| Attack paths eliminated | 7 | **0 (7 eliminated)** | `identity/graph/attack-paths.json` |
| Analyst-minutes saved / run | TBD | TBD | automation timing harness (Phase 11, pending) |
