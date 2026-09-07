# Security Automation

Python that removes analyst toil across the pipeline. All light, file-based, reproducible.

| Stage | Script | What it does |
|---|---|---|
| Normalize | `normalize/normalize.py` | Multi-source raw logs → one schema → DuckDB |
| Detect | `detect/run_sigma.py` | Compile + run Sigma detections → alerts |
| Coverage | `detect/coverage.py` | Generate ATT&CK matrix + Navigator layer from rules |
| **Triage (SOAR)** | `soar/triage.py` | Enrich alerts w/ threat-intel, score/prioritize, correlate into a case, measure time saved |
| Metrics | `report/metrics.py` | Compute coverage/window/FP from evidence |
| Report | `report/build_report.py` | Render the static dashboard |

## SOAR triage playbook (`soar/triage.py`)
Does an analyst's first pass automatically:
1. **Enrich** each alert against the threat-intel feed (`threat-intel/iocs-feed.json`) → reputation + actor attribution.
2. **Score** = severity + intel reputation + crown-jewel-technique bonus → **P1..P4** + a recommended action from a
   technique→response playbook.
3. **Correlate** alerts sharing a source IP/actor into incident **clusters** (25 alerts → 1 primary cluster of 21,
   all attributed to SCATTERED SABLE).
4. **Auto-write** a machine case file: [`../incident-response/auto-generated-case.md`](../incident-response/auto-generated-case.md).
5. **Measure** analyst-minutes saved with **stated assumptions** (4 min/alert triage + 20 min case correlation) →
   ~**120 min/run** vs sub-second automated. Output: [`../metrics/automation-metrics.json`](../metrics/automation-metrics.json).

Run: `make triage` (or `python automation/soar/triage.py`).

> Honesty note: the time-saved figure is an *estimate* from documented per-alert assumptions, not a stopwatch on a real
> analyst — the point is a defensible, transparent model, and the automation genuinely produces the enriched output.

**Enterprise equivalent:** Tines / Shuffle / Splunk SOAR playbooks writing to Jira/ServiceNow; here a Python playbook
writing Markdown + JSON. Same workflow, same decisions.
