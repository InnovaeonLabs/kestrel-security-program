# Cloud & IAM Security (Phase 6)

Kestrel Pay's AWS footprint as **Terraform**, deliberately misconfigured, scanned with a **real IaC scanner (Checkov)**,
analyzed for **attack paths**, and remediated — connected to the CloudTrail detections and the incident.

## Static IaC scan (Checkov) — real evidence
`.venv/Scripts/python -m checkov.main -d cloud-security/terraform --compact` → [`../evidence/logs/checkov-run.txt`](../evidence/logs/checkov-run.txt)

**Result: 41 failed IaC checks + 1 hardcoded secret** (16 passed) on [`terraform/main.tf`](terraform/main.tf). Headline findings:
| Finding | Check | Crown jewel at risk | Fix (in `terraform/hardened.tf.example`) |
|---|---|---|---|
| Wildcard IAM policy (`Action:*`,`Resource:*`) | CKV2_AWS_40 | AWS account (AST-002) | Scope to specific secret + bucket |
| S3 bucket public (policy `Principal:*`, no public-access block) | CKV_AWS_53/54, CKV2_AWS_6 | Statements/backups (AST-010) | Block Public Access + private policy |
| S3 unencrypted / no versioning | CKV_AWS_145/21 | Data at rest | KMS SSE + versioning |
| Security group open 0.0.0.0/0 all ports | CKV_AWS_24 | API/network (AST-004) | 443 from LB SG only |
| Secrets Manager: no rotation | CKV2_AWS_57 | Signing key (AST-001) | 30-day rotation |
| RDS public + unencrypted + hardcoded password | CKV_AWS_16/17, CKV_SECRET_6 | Ledger (AST-003) | Private, KMS, managed password |

## Attack-path analysis (identity + cloud)
`python identity/graph/attack_paths.py` → [`../identity/graph/attack-paths.md`](../identity/graph/attack-paths.md)

From a phished engineer (`user:leo.kim`) to the crown jewels:
- **Current state: 7 attack paths** (3 to the signing key, 2 to AWS-admin, 2 to the ledger).
- **Target state (least-privilege + SCP + IMDSv2): 0 paths — 7 eliminated.**

The over-privileged `kestrel-api-task` role (the wildcard above) is the single edge that turns an SSRF/credential theft
into full account control — the same path the SCATTERED SABLE incident used (steps 9–11).

## Runtime detections (CloudTrail)
The misconfigurations above are what make the cloud attack *possible*; these detections catch it *happening*:
- **KP-0030** Secrets Manager access by assumed role (signing-key read)
- **KP-0031** IAM privilege escalation (AdministratorAccess attached)
- **KP-0032** S3 bucket policy made public

## Lab vs enterprise
Lab: Terraform + Checkov (static) + CloudTrail **sample** + a Python attack-path graph. Enterprise: the same Terraform
in CI + a CSPM/CNAPP (e.g., Prowler/GuardDuty/Config) on a live account + BloodHound/AzureHound over the real directory.
Same findings, same reasoning — no running cloud or spend required.
