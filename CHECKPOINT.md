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
| 1 | Business & asset modeling | 🟡 IN PROGRESS | `docs/architecture/company-profile.md`, `assets/asset-inventory.csv`, `docs/threat-model/threat-model.md`, `docs/risk/risk-register.csv` |
| 2 | Architecture & lab deployment | ⬜ TODO | `docs/architecture/`, `range/`, `docker-compose.yml` |
| 3 | Logging / telemetry foundation | ⬜ TODO | `automation/normalize/`, Sysmon config, `range/data/` |
| 4 | Baseline security controls | ⬜ TODO | `config/`, hardening docs |
| 5 | Vulnerability & exposure assessment | ⬜ TODO | `vulnerability-management/` |
| 6 | App / API / Cloud / Identity security | ⬜ TODO | `appsec/`, `cloud-security/`, `identity/` |
| 7 | Detection engineering | ⬜ TODO | `detections/sigma/`, `automation/detect/` |
| 8 | Controlled adversary simulation | ⬜ TODO | `attack-scenarios/scattered-sable/` |
| 9 | Incident response & DFIR | ⬜ TODO | `incident-response/`, `dfir/` |
| 10 | Purple-team improvement | ⬜ TODO | `purple-team/` |
| 11 | Automation | ⬜ TODO | `automation/` |
| 12 | GRC / risk / architecture review | ⬜ TODO | `docs/risk/`, `docs/architecture/target-state.md` |
| 13 | Resilience & recovery | ⬜ TODO | `resilience/` |
| 14 | Measurement & posture comparison | ⬜ TODO | `metrics/` |
| 15 | Portfolio / GitHub packaging | ⬜ TODO | `README.md`, `reports/` |
| 16 | Resume / LinkedIn / interview prep | ⬜ TODO | `reports/career/` |

## Decisions log (why we did it this way)
- **D-001** Rejected multi-VM SOC (GOAD/Security Onion): won't fit 8 GB/2-core. Chose SIEM-less detection-as-code. *Tradeoff documented in `docs/architecture/lab-vs-enterprise.md` (Phase 2).*
- **D-002** Analytics = DuckDB + Sigma-compiled-to-SQL instead of Elastic (RAM). Static HTML dashboard instead of always-on Kibana.
- **D-003** Endpoint telemetry from the real Windows host via Sysmon + PowerShell logging (no Windows VM).
- **D-004** Cloud = Terraform + Checkov (static) + CloudTrail sample + Python policy-sim, not a running cloud; LocalStack optional if RAM allows.
- **D-005** Emulated adversary "SCATTERED SABLE" = fictional financially-motivated eCrime actor (Scattered-Spider-flavored identity/cloud/SaaS TTPs) to showcase modern fintech-relevant + high-differentiation domains.

## Open items / next action
- **NEXT:** finish Phase 1 (validate threat model coverage, seed risk register with top 10 risks), then Phase 2 range compose file.

## Metric placeholders (fill from real evidence — never invent)
| Metric | Baseline | Post-improvement | Source of truth |
|---|---|---|---|
| ATT&CK technique detection coverage (scenario) | TBD | TBD | `metrics/coverage.json` from `automation/detect` |
| MTTD (SCATTERED SABLE) | TBD | TBD | `incident-response/timeline.csv` |
| FP rate (top-5 detections) | TBD | TBD | alert counts pre/post tuning |
| Critical/High vulns remediated | TBD | TBD | `vulnerability-management/register.csv` |
| Attack paths eliminated | TBD | TBD | `identity/graph/` before/after |
| Analyst-minutes saved / run | TBD | TBD | automation timing harness |
