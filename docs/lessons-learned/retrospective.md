# Project Retrospective & Lessons Learned

## What went well
- **One coherent story** (SCATTERED SABLE) tied every discipline together — no disconnected mini-labs.
- **Testable detections** — the 42 unit tests turn "I wrote rules" into "my detections are verified."
- **Honest constraints** — turning an 8 GB laptop limitation into a SIEM-less design (and documenting the enterprise
  equivalent) demonstrated judgment better than faking a big environment.
- **Everything reproduces** with `make`, so a skeptic can re-run it.

## What was hard / what I learned
- **Telemetry ingestion is the foundation** — a JSON-escaping bug silently dropped Sysmon events; I only caught it by
  checking source counts. Validate ingestion before trusting detections.
- **Prioritization is about attack paths, not CVSS** — modeling the graph made the "fix this first" order obvious.
- **Detection tuning is a tradeoff** — thresholds that catch the attack while holding 0 false positives took iteration.

## What I'd do next (roadmap)
- Add streaming detection + a real IdP log source; add EDR-grade endpoint coverage.
- Close the documented ATT&CK gaps (T1566/T1110/T1114.003).
- Add a SOAR-style playbook chaining triage → enrichment → ticket, and measure analyst-minutes saved.
- Optional live LocalStack scenario for one cloud path.

## Skills this project makes visible (recruiter-radar)
1. Translating technical issues into business/PCI/SOC 2 risk. 2. Measuring security effectiveness (before/after).
3. Communicating with executives. 4. Documenting decisions + tradeoffs. 5. Prioritizing by attack path, not fixing
everything blindly. 6. Understanding telemetry dependencies. 7. Showing detection limitations honestly.
8. Validating remediation (retest). 9. Automating repetitive work. 10. Protecting stakeholders, not just systems.
