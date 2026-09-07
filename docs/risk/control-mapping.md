# Control Mapping — NIST CSF 2.0 · CIS Controls v8 · SOC 2

Cybersecurity exists to manage business risk. This maps the project's controls to recognized frameworks and to the
**evidence** that they operate — the difference between "we say we do X" and "here is X running." Not checkbox
compliance: each row states the risk it reduces.

## NIST CSF 2.0 + CIS v8
| CSF 2.0 Function | Control implemented | CIS v8 | Evidence | Risk reduced |
|---|---|---|---|---|
| **GV** (Govern) | Risk register + owners + review cadence | 1,17 | `docs/risk/risk-register.csv` | program-level |
| **ID** (Identify) | Asset inventory + threat model | 1,2 | `assets/`, `docs/threat-model/` | R-01..R-12 |
| **ID.RA** | Risk-based vuln management | 7 | `vulnerability-management/register.csv` | R-03,R-05,R-06 |
| **PR.AA** (Identity/Access) | Least-priv, FIDO2, RBAC, attack-path graph | 5,6 | `identity/`, `cloud-security/` | R-01,R-02,R-10 |
| **PR.DS** (Data) | KMS encryption, secret rotation, S3 BPA | 3 | `cloud-security/hardened.tf.example` | R-04,R-06 |
| **PR.PS** (Platform) | Secure config, hardened API, IaC scan | 4,16 | `appsec/`, Checkov | R-03,R-06,R-08 |
| **PR.PS (SDLC)** | CI secret/SAST/SCA/IaC gates | 16 | `.github/workflows/ci.yml` | R-05 |
| **DE.CM** (Detect) | 15 tested Sigma detections + coverage matrix | 8,13 | `detections/`, `evidence/alerts/` | R-01..R-11 |
| **RS** (Respond) | IR plan + incident + exec summary | 17 | `incident-response/` | all |
| **RC** (Recover) | Backup/recovery priorities + RTO/RPO | 11 | `resilience/` | R-12 |

## SOC 2 evidence hooks (Trust Services Criteria)
Kestrel's customers require SOC 2; auditors want *operating* evidence, not intent.
| TSC | Criterion | Evidence this project produces |
|---|---|---|
| CC6.1 | Logical access / least privilege | attack-path graph 7→0, scoped IAM (`identity/`, `cloud-security/`) |
| CC6.6 | Boundary protection | SG hardening, WAF/rate-limit (`cloud-security/`, nginx) |
| CC7.1 | Detection of anomalies | Sigma detections + coverage matrix + alerts |
| CC7.2 | Monitoring / incident detection | telemetry pipeline + dashboard |
| CC7.3/7.4 | Incident response | INC-2026-0821 report + exec summary |
| CC8.1 | Change management (secure SDLC) | CI gates, signed-commit target, IaC scan |

## Honest note
This demonstrates control *design + operating evidence* at lab scale; a real SOC 2 Type II needs the controls operating
over a 3–12 month audit window with independent testing. The point is that this project already produces the *kind of
evidence* an auditor asks for.
