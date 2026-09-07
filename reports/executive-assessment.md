# Executive Security Assessment — Kestrel Pay

**Audience:** CEO / Board. **Bottom line up front:** the program moved Kestrel Pay from *blind and exploitable* to
*monitored, defended, and measurably improved* — using only free tooling.

## Business context
Kestrel Pay handles other companies' money and customer card/bank data through an API. A breach means fraud,
regulatory penalties (PCI / privacy), and loss of the SOC 2 attestation customers require. The company is a natural
target for financially-motivated attackers and had no security monitoring and no budget for commercial tools.

## What we did
Modeled the business and its crown jewels, built visibility across identity, endpoint, API, and cloud, engineered
tested detections, ran a realistic attack end-to-end, responded to it, fixed the root causes, and measured the result.

## Results (evidence-backed)
| Outcome | Before | After |
|---|---|---|
| Can we detect an intrusion? | No detections | 100% of the attack's techniques detected |
| Noise (false alarms) | n/a | 0 on normal activity |
| Time to detect before impact | none | ~7 minutes of containment window |
| Paths from a stolen laptop to the signing key | 7 | 0 |
| Cloud misconfigurations caught before deploy | 0 | 41 |
| Dangerous app flaws fixed & retested | 0 | 2 critical + more by control |

## Top residual risks & the plan
1. **Phishing-resistant MFA not yet rolled out** (root cause of the intrusion) — planned, tracked (R-01).
2. **Two detection gaps** (credential stuffing, mailbox rules) — on the backlog with owners.
3. Controls need to *operate over time* for SOC 2 Type II — this establishes the evidence pattern.

## Recommendation
Fund the small set of changes in the risk register (mostly configuration, not spend). They remove the root cause —
treating identity and cloud permissions as the primary perimeter — and protect revenue, customers, and the SOC 2 standing.
