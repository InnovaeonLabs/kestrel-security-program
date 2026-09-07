# Identity Security & Attack-Path Analysis (Phase 6)

Identity is Kestrel Pay's real perimeter. This covers identity detections, the JML/least-privilege model, and a
**graph-based attack-path analysis** (the high-differentiation piece most portfolios skip).

## Attack-path graph (BloodHound-lite, networkx)
`python identity/graph/attack_paths.py` → [`graph/attack-paths.md`](graph/attack-paths.md) + `graph/attack-paths.json`

- Models principals, groups, hosts, roles, secrets, data as a directed graph.
- Finds every path from a phished engineer to the crown jewels.
- **Current: 7 paths → Target (least-privilege): 0 → 7 eliminated.**

## Identity detections
- **KP-0001** MFA fatigue (≥3 push denials / 10 min)
- **KP-0002** OAuth token grant following fatigue (session theft)
- (backlog gap) **T1110** credential stuffing — velocity rule on `login_failure`
- (backlog gap) **T1114.003** mailbox forwarding-rule creation — needs Workspace/Graph audit source

## Identity controls (target state)
| Control | Why | Maps to |
|---|---|---|
| Phishing-resistant MFA (FIDO2) + number-matching | Kills MFA-fatigue root cause (R-01) | NIST PR.AA, CIS 6 |
| Conditional access (geo/device) | Blocks foreign-IP token use | PR.AA |
| Least-privilege RBAC + JML process | Shrinks blast radius | PR.AA, CIS 5/6 |
| Short session/token TTL + revocation | Limits stolen-token value | PR.AA |
| Service-account scoping + rotation | svc_payouts abuse (R-04) | PR.DS |

## Lab vs enterprise
Lab models the directory as a graph and Okta-style logs as samples. Enterprise: BloodHound/AzureHound over the live
directory + Okta/Entra sign-in logs + an ITDR tool. The *reasoning* (paths to crown jewels, least-privilege to cut them)
is identical.
