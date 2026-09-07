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
| 4 | Baseline security controls | ⬜ TODO | `config/`, hardening docs (partly done via KESTREL_HARDENED toggle) |
| 5 | Vulnerability & exposure assessment | ⬜ TODO | `vulnerability-management/` |
| 6 | App / API / Cloud / Identity security | 🟡 PARTIAL | `appsec/` (8 findings + retest, 4 tests pass); cloud/identity TODO |
| 7 | Detection engineering | ✅ DONE | `detections/sigma/` (15 rules), `automation/detect/run_sigma.py`, `detections/tests/` (32 tests pass), `detections/coverage/` |
| 8 | Controlled adversary simulation | ✅ DONE | `attack-scenarios/scattered-sable/run.py` (15-step chain), `timeline.json` |
| 9 | Incident response & DFIR | ✅ DONE | `incident-response/INC-2026-0821-*.md` + `exec-summary.md`, `dfir/investigation-notes.md` + `iocs.csv` |
| 10 | Purple-team improvement | ✅ DONE | `purple-team/scattered-sable-purpleteam.md` (before/after measured) |
| 11 | Automation | 🟡 PARTIAL | `automation/normalize`, `automation/detect`, `automation/report/metrics.py`; enrichment/triage/report-gen TODO |
| 12 | GRC / risk / architecture review | ⬜ TODO | `docs/risk/`, `docs/architecture/target-state.md` |
| 13 | Resilience & recovery | ⬜ TODO | `resilience/` |
| 14 | Measurement & posture comparison | 🟡 PARTIAL | `metrics/metrics.json` (computed); dashboard TODO |
| 15 | Portfolio / GitHub packaging | ⬜ TODO | `README.md`, `reports/` |
| 16 | Resume / LinkedIn / interview prep | ⬜ TODO | `reports/career/` |

## Decisions log (why we did it this way)
- **D-001** Rejected multi-VM SOC (GOAD/Security Onion): won't fit 8 GB/2-core. Chose SIEM-less detection-as-code. *Tradeoff documented in `docs/architecture/lab-vs-enterprise.md` (Phase 2).*
- **D-002** Analytics = DuckDB + Sigma-compiled-to-SQL instead of Elastic (RAM). Static HTML dashboard instead of always-on Kibana.
- **D-003** Endpoint telemetry from the real Windows host via Sysmon + PowerShell logging (no Windows VM).
- **D-004** Cloud = Terraform + Checkov (static) + CloudTrail sample + Python policy-sim, not a running cloud; LocalStack optional if RAM allows.
- **D-005** Emulated adversary "SCATTERED SABLE" = fictional financially-motivated eCrime actor (Scattered-Spider-flavored identity/cloud/SaaS TTPs) to showcase modern fintech-relevant + high-differentiation domains.

## Open items / next action
- **NEXT:** Phase 8 — build the SCATTERED SABLE emulation (`attack-scenarios/scattered-sable/run.py`) that drives the
  live/vulnerable API so the App/API + LLM rules fire; capture before/after. Then Phase 9 (IR/DFIR) writes the incident
  from the resulting alerts. Phases 4/5/6 (baseline/vuln-mgmt/app-cloud-identity) can be authored alongside.
- Detection pipeline is live: `make detect` → 8 alerts/8 techniques on current data; `make test` → 32 pass.
- Coverage: 13 techniques with tested detections; documented gaps in `detections/coverage/coverage-matrix.md`.

## Metrics (computed from real evidence — metrics/metrics.json)
| Metric | Baseline | Post-improvement | Source of truth |
|---|---|---|---|
| ATT&CK chain detection coverage | 0% | **100% (12/12)** | `metrics/metrics.json` |
| Attack steps detected | 0/15 | **15/15** | `metrics/metrics.json` |
| Alerts on the intrusion | 0 | **22** | `evidence/alerts/alerts.jsonl` |
| FP rate on benign baseline | n/a | **0 / 40** | `evidence/alerts/detection-run.txt` |
| Detection-opportunity window before impact | none | **~6 min** | `metrics/metrics.json` |
| Detection unit tests | 0 | **32 pass** | `evidence/alerts/pytest-detections.txt` |
| Critical/High app flaws remediated + retested | 0 | **2 (JWT, prompt-injection) + 6 by rule** | `appsec/tests` (4 pass) |
| Attack paths eliminated | TBD | TBD | `identity/graph/` (Phase 6, pending) |
| Analyst-minutes saved / run | TBD | TBD | automation timing harness (Phase 11, pending) |
