# Phase 0 — Executive Project Charter

**Project:** Kestrel Pay Security Program (*Project KESTREL*)
**Sponsor (role-played):** CISO, Kestrel Pay, Inc.
**Author:** Independent portfolio project
**Date:** 2026-09-06

## 1. Purpose
Stand up, secure, attack, defend, and continuously improve the security program of a realistic small fintech, and
produce portfolio-grade evidence that the builder can **understand, attack, defend, monitor, investigate, improve,
govern, and communicate** an organization's security posture.

## 2. Business problem (the "why")
Kestrel Pay handles other companies' money and cardholder data through an API. A single breach = regulatory penalties
(PCI/state privacy), loss of SOC 2 attestation, churn of every SMB platform that embedded the API, and existential
reputational damage. The company is a natural target for **financially-motivated eCrime** yet has a tiny security team
and no budget for commercial security tooling. The program must reduce real risk to the crown jewels using **free/OSS**
capabilities and prove the risk went down.

## 3. Objectives (measurable)
1. Establish telemetry across endpoint, application/API, identity, cloud, and CI/CD.
2. Engineer **tested** detections (detection-as-code) mapped to MITRE ATT&CK for the org's most likely attack paths.
3. Emulate a realistic multi-stage intrusion and run it fully through detect→investigate→respond→remediate→retest.
4. Demonstrate a **measurable** posture improvement (coverage, MTTD, FP rate, remediated risk).
5. Tie every technical control to **business risk** and a recognized framework (NIST CSF 2.0, CIS v8).

## 4. Scope
**In scope:** the fictional Kestrel Pay environment, recreated as a $0 local lab (containers, Python, real Windows-host
telemetry, Terraform/IaC, CI). All offensive activity is **benign, reversible, lab-only**.
**Out of scope:** any real third party, employer, or internet host; live malware; any paid product; destructive actions.

## 5. Success criteria
The builder can truthfully state: *"I designed a small organization's security program, modeled its risks and attack
surface, deployed and secured the environment, simulated authorized adversary behavior, collected telemetry, engineered
and tested detections, investigated an incident, improved controls, automated security workflows, assessed risk,
measured the improvement, and documented both the technical and business impact"* — **with an artifact backing every clause.**

## 6. Constraints & assumptions
- **$0** total cost; free/OSS/community/free-tier only.
- Runs on a 2-core / 8 GB laptop → **one range profile at a time**, no heavyweight SIEM, telemetry stored as data on disk.
- Where the lab diverges from an enterprise, the **enterprise equivalent is documented** (no pretending a laptop is a Fortune 500 network).

## 7. Stakeholders (fictional org) & what they depend on
| Stakeholder | Depends on |
|---|---|
| SMB platform customers | API availability, integrity of payments, confidentiality of their end-users' data |
| End-consumers (customers' customers) | Their card/bank data not being stolen |
| Engineering | CI/CD integrity, secrets not leaking, being able to ship safely |
| Finance/Ops | No fraudulent transfers, no BEC |
| Executives/Board | SOC 2 attestation, no breach headlines, regulatory standing |
| Regulators / auditors | Evidence of controls operating effectively |

## 8. High-level phase plan
See [`../CHECKPOINT.md`](../CHECKPOINT.md) for live status. Phases 0–16 (charter → lab → telemetry → controls →
vuln mgmt → app/cloud/identity → detections → adversary sim → IR/DFIR → purple team → automation → GRC → resilience →
metrics → packaging → career).

## 9. Deliverables (portfolio artifacts)
Executive & technical assessments, architecture (current/target), threat model, asset inventory, risk register,
vuln-mgmt report, detection catalogue, ATT&CK coverage matrix, purple-team report, incident report + exec summary,
DFIR notes, threat-intel report, cloud/IAM assessment, app/API report, DevSecOps/supply-chain assessment, automation
docs, metrics dashboard, lessons-learned, current-vs-target assessment, final retrospective, and career collateral.

## 10. Definition of done for the whole project
Every item in §9 exists as a real file, every metric in `metrics/` is computed from real evidence, and the README's
30-second view is fully backed by linked artifacts.
