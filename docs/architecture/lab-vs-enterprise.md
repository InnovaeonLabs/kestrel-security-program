# Lab Implementation vs. Real-World Enterprise Equivalent

The single most important judgment call in this project: **the lab host is a 2-core / 8 GB laptop.** A conventional
multi-VM "home SOC" (Windows DC + endpoints + Security Onion + a heavyweight SIEM) needs 32–64 GB RAM and will not
run here. Rather than fake an environment that can't exist on this hardware, I made a deliberate architectural choice —
**SIEM-less, detection-as-code, telemetry-as-data** — and I document the enterprise equivalent for every shortcut so
the *understanding* is visible even where the *implementation* is scaled down.

## The core tradeoff (decision D-001/D-002)
| | Chosen (lab) | Rejected (enterprise-style) |
|---|---|---|
| **Benefit** | Runs on 8 GB; portable; vendor-neutral; fully reproducible via `make`; detections are code with unit tests | Realistic scale; live dashboards; native alerting |
| **Limitation** | No live streaming SIEM UI; batch detection instead of real-time; single host | Won't fit the hardware; heavy to reproduce; cost |
| **Cost/resource** | ~0.5 GB peak; $0 | 32–64 GB RAM; often paid tiers |
| **Operational** | Analyst runs `make detect`; results are files | Always-on SOC console |
| **Why chosen** | The brief demands $0 + reproducibility; the constraint showcases better judgment than a bloated clone |

## Component-by-component mapping
| Capability | Lab implementation | Real-world enterprise equivalent |
|---|---|---|
| SIEM / analytics | DuckDB over JSONL + Sigma-compiled-to-SQL (batch) | Splunk / Elastic / Microsoft Sentinel / Chronicle (streaming) |
| Dashboards | Generated static HTML + Mermaid | Kibana / Splunk dashboards / Grafana |
| Endpoint telemetry | Sysmon + PowerShell logging on the real Windows host | EDR (CrowdStrike/Defender for Endpoint/SentinelOne) fleet-wide |
| Log shipping | Volume mount + Python normalizer | Fluent Bit / Winlogbeat / Vector → log pipeline |
| Identity / SSO | Modeled IdP + JWT + Okta-style log **samples** | Okta / Entra ID with real sign-in logs + ITDR |
| Identity attack paths | `networkx` graph, hand-modeled | BloodHound / AzureHound against the real directory |
| Cloud | Terraform + Checkov (static) + CloudTrail **sample** + Python policy-sim | Live AWS + CloudTrail + GuardDuty + Config + an CNAPP/CSPM |
| Vulnerable app | Self-built FastAPI app (I control the telemetry) | The real production application + WAF |
| DB | SQLite (Postgres profile optional) | RDS/Aurora with audit logging |
| Adversary emulation | Benign, reversible atomics in a scoped folder | Full C2 + red-team infra in an isolated range |
| Malware analysis | EICAR + self-authored benign artifact, static+behavioral | Detonation sandbox (Cuckoo/CAPE/Joe) on real samples |
| Threat intel | MISP-lite files + STIX samples | MISP/OpenCTI + commercial feeds |
| Ticketing/SOAR | Python scripts + Markdown case files | Jira/ServiceNow + Tines/Shuffle/Splunk SOAR |

## What is *fully real* here (not simulated)
- Real Windows endpoint telemetry (Sysmon/PowerShell) captured on the host.
- Real, executable detection logic (Sigma → SQL) with **passing unit tests**.
- Real IaC misconfigurations caught by a real scanner (Checkov) in real CI (GitHub Actions).
- Real, working vulnerable API whose flaws are exploitable in the lab and produce genuine telemetry.
- Real before/after measurement computed from the actual alert output.

## Honest limitations (stated, not hidden)
- Detection is **batch**, not streaming → MTTD here measures *analysis-to-alert*, and I note where an enterprise would
  be near-real-time.
- Single-node telemetry → no cross-host correlation at scale; the schema is designed to support it if scaled out.
- Cloud attacks are analyzed against **sample** CloudTrail + policy simulation rather than a live account (an optional
  LocalStack scenario is provided for one live path if the host has headroom).

This document is itself an interview asset: it demonstrates recognizing tradeoffs, resource constraints, and the gap
between a lab and production — exactly the judgment hiring teams look for.
