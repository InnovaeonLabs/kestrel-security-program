# Threat Intelligence (Phase 16)

Intel lifecycle applied, not IOC copy-paste: `COLLECT → EVALUATE → ENRICH → APPLY → DETECT → RESPOND`.

| Stage | What we did | Artifact |
|---|---|---|
| Collect | Curated indicators from the intrusion + known test IOCs | `iocs-feed.json` |
| Evaluate | Scored reputation/confidence; attributed to SCATTERED SABLE | `iocs-feed.json` |
| Enrich | Auto-enrich every alert with feed hits (reputation/actor) | `../automation/soar/triage.py` |
| Apply | Feed hits raise triage priority; actor TTPs prioritize detections | `scattered-sable-profile.md` |
| Detect | Lookalike domain + C2 IP power KP-0040/0021; TTPs map to the catalogue | `../detections/` |
| Respond | IOCs become block/hunt actions in the incident | `../incident-response/`, `../dfir/iocs.csv` |

## How intel *changes decisions* (the point)
- **Prioritization:** an alert whose source IP matches a `malicious`/`SCATTERED SABLE` feed entry is auto-escalated —
  see the triage scores in `../evidence/alerts/triaged-alerts.jsonl`.
- **Hunting:** the actor profile gives concrete pivots (`45.77.0.10`, `cdn.sable-c2.example`, `sable@proton.example`).
- **Risk:** the actor's known BEC + MFA-fatigue playbook raised likelihood on risks R-01/R-07.

**Enterprise equivalent:** MISP/OpenCTI ingesting STIX/TAXII feeds + commercial intel; here a small JSON feed + a Python
enricher. Same lifecycle and the same decisions driven by it.
