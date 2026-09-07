# Kestrel Pay, Inc. — Fictional Organization Profile

> Fictional company used as the subject of *Project KESTREL*. Any resemblance to real entities is coincidental.

## Snapshot
| Attribute | Detail |
|---|---|
| **Name** | Kestrel Pay, Inc. ("Kestrel") |
| **Industry** | Financial technology (fintech) — embedded payments infrastructure |
| **Business model** | B2B2C SaaS. Sells an **embedded payments + invoicing API** that SMB software platforms drop into their products to charge *their* customers. Revenue = % of payment volume + monthly platform fees. |
| **Stage / size** | Series A, ~**45 employees**, remote-first (US + EU contractors) |
| **Customers** | ~**300 SMB SaaS platforms**; those platforms serve ~**120,000 end-consumers** whose card/bank data flows through Kestrel |
| **Founded** | 2022 |
| **HQ** | Nominal Delaware C-corp; no physical office (remote-first) |

## What makes them a target
Kestrel sits in the **money flow**. Attackers who compromise it can: divert settlements, harvest cardholder/bank data
at scale, commit invoice/BEC fraud, or ransom the payment pipeline. It's a **high-value, low-headcount** target — the
classic profile eCrime groups prefer.

## Technical environment (recreated at $0 in the lab)
| Layer | Real-world (fictional) | Lab recreation |
|---|---|---|
| Identity / SSO | Google Workspace + Okta-style IdP, MFA | Modeled IdP + JWT auth in the API; Okta-style log **samples**; identity graph in `networkx` |
| Endpoints | MacBooks + a few Windows admin boxes | **Real Windows 11 host** w/ Sysmon + PowerShell logging |
| Product | Payments/invoicing **API** (Python) + Postgres + Redis, behind nginx | FastAPI `kestrel-api` + SQLite/Postgres + nginx in Docker (light profile) |
| Cloud | AWS (prod account): ECS, RDS, S3, IAM, KMS, CloudTrail | **Terraform** definitions + Checkov scan + CloudTrail **sample** + Python policy-sim |
| Source / CI-CD | GitHub + GitHub Actions | Local repo + Actions workflow (`act`/CI) with gitleaks, Semgrep, Trivy, pip-audit, Checkov |
| Secrets | AWS Secrets Manager / KMS-wrapped payment-signing keys | Modeled secrets + planted-secret scenario + scanning |
| SaaS | Slack, Google Workspace, Notion, HubSpot | Modeled via log samples + SaaS-risk register |
| Data stores | Cardholder tokens, bank details, ledger, PII | SQLite/Postgres seeded with **synthetic** data |

## Crown jewels (ranked)
1. **Payment-signing keys / KMS** — signing keys that authorize money movement. Compromise = direct fraud.
2. **Production AWS account + IAM** — control plane over everything.
3. **Customer cardholder & bank data (the ledger DB)** — PCI + breach liability.
4. **CI/CD pipeline & source** — supply-chain path to prod; a poisoned build reaches all customers.
5. **Admin/engineer identities** — the keys to 1–4; identity is the real perimeter.

## Regulatory & contractual obligations
- **PCI DSS** (handles cardholder data) — even if largely tokenized, SAQ/scope obligations apply.
- **SOC 2 Type II** — customers won't sign without it; controls must *operate over time* with evidence.
- **State privacy laws** (e.g., CCPA-style) — breach notification, data-subject rights.
- **GLBA-flavored** safeguards expectations for financial data.
> These drive the GRC/control-mapping work in `docs/risk/` and give business teeth to every finding.

## Threat profile (summary — full model in `docs/threat-model/`)
| Actor | Motivation | Relevance |
|---|---|---|
| **Financially-motivated eCrime** ("SCATTERED SABLE" emulation) | Money | Primary. Identity/social-eng → SaaS/cloud → API/ledger → fraud/extortion |
| **BEC / invoice-fraud crews** | Money | High — a payments company is a juicy BEC target |
| **Credential-stuffing / carding bots** | Money | High — automated abuse of the payments API |
| **Malicious/negligent insider** | Money / mistake | Medium — small team, broad access |
| **Supply-chain / dependency attacker** | Access at scale | Medium — one poisoned dep reaches 300 platforms |
| **Opportunistic scanners** | Whatever's exposed | Constant background noise |
