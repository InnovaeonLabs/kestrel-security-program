# Security Architecture — Current / Initial State

This is the **"before"** picture: the environment as Kestrel Pay runs it today, with minimal security engineering.
The target/improved state is in [`target-state.md`](target-state.md) (built out in Phase 12) and the delta is what the
whole project delivers.

## Current-state diagram
```mermaid
flowchart TB
  subgraph Internet
    Cust[SMB platforms / end-users]
    Att[Threat actors]
  end
  subgraph Prod["AWS prod (weakly segmented)"]
    NGX[nginx]:::edge
    API[Kestrel Pay API + LLM copilot]:::app
    DB[(Ledger / cardholder DB)]:::data
    S3[(S3 buckets)]:::data
    SEC[[Secrets / KMS signing keys]]:::data
    IAM[IAM roles - over-broad]:::risk
    CT[CloudTrail on, unmonitored]:::risk
  end
  subgraph SaaS
    IDP[IdP/SSO + basic MFA]:::id
    GW[Google Workspace]:::id
    GH[GitHub + Actions - no gates]:::risk
  end
  Ep[Employee endpoints - no telemetry]:::risk

  Cust -->|TLS| NGX --> API --> DB
  API --> SEC
  API --> S3
  Att -.->|phish/social-eng| IDP
  Att -.->|API abuse/scan| NGX
  Ep --> IDP --> GH -->|OIDC deploy| IAM --> API
  IAM --- SEC

  classDef edge fill:#e6f0ff,stroke:#369;
  classDef app fill:#eef,stroke:#66c;
  classDef data fill:#fde,stroke:#c39;
  classDef id fill:#efe,stroke:#3a3;
  classDef risk fill:#fee,stroke:#c33,stroke-dasharray:4 3;
```

## Current-state gaps (the problem statement, in one place)
| # | Gap | Consequence | Fixed in phase |
|---|-----|-------------|----------------|
| G1 | **No centralized telemetry / detections** | Attacks are invisible; no IR possible | 3, 7 |
| G2 | **No endpoint visibility** | Token theft / LotL undetected | 3, 7 |
| G3 | **Over-broad cloud IAM, unmonitored CloudTrail** | Priv-esc & data access unnoticed | 6, 7 |
| G4 | **No CI/CD security gates** | Secrets & vulns ship to prod | 5, 6 |
| G5 | **API authz/validation weaknesses** | IDOR/SQLi/SSRF → data & money | 5, 6 |
| G6 | **Basic MFA, no identity detection** | Account takeover is easy & silent | 6, 7 |
| G7 | **Secrets in code/history, no access alerting** | Signing keys reachable | 5, 6, 7 |
| G8 | **No IaC/storage scanning** | Public S3 / misconfig risk | 5, 6 |
| G9 | **No vuln-management lifecycle** | Risk unprioritized | 5 |
| G10 | **No GRC linkage** | Can't prove SOC 2 / prioritize by risk | 12 |

## Design constraints (host reality) → architecture stance
The lab host is 2-core / 8 GB. Enterprise SIEM stacks won't run. Stance:
**telemetry is data on disk → queried on demand with DuckDB → detections are code (Sigma) → dashboards are generated
static artifacts.** Rationale, tradeoffs, and the **enterprise equivalent** for each choice are in
[`lab-vs-enterprise.md`](lab-vs-enterprise.md) (Phase 2).
