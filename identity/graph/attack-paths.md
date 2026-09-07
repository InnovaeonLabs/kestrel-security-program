# Identity & Cloud Attack-Path Analysis

Entry point: **user:leo.kim** (phished engineer). Crown jewels: `secret:signing-key`, `cloud:aws-admin`, `data:ledger`.

## Result (computed)
- Attack paths to crown jewels — **current: 7**, **target (least-privilege): 0**
- **Attack paths eliminated: 7**

Example current path to the signing key:

`user:leo.kim -> host:KP-LAPTOP-07 -> role:kestrel-api-task -> cloud:aws-admin -> secret:signing-key`

## What eliminates them
- Scope `kestrel-api-task` to only the secrets/resources it needs (remove wildcard admin).
- SCP guardrail denying `iam:Attach*` / `*:*` on the deploy path.
- IMDSv2 + SSRF allow-list so a compromised laptop/app can't assume the task role.

## Current-state graph (risky edges dashed)

```mermaid
flowchart LR
  user_leo.kim -- HasSession --> host_KP-LAPTOP-07
  user_leo.kim -- MemberOf --> group_engineers
  host_KP-LAPTOP-07 -. CanAssume(SSRF/creds) .-> role_kestrel-api-task
  group_engineers -- CanAccess --> saas_github
  saas_github -- Triggers --> cicd_actions
  cicd_actions -- AssumesViaOIDC --> role_deploy
  role_deploy -. AttachPolicy*(wildcard) .-> cloud_aws-admin
  role_kestrel-api-task -. Admin*(wildcard) .-> cloud_aws-admin
  role_kestrel-api-task -. CanRead(unscoped) .-> secret_signing-key
  cloud_aws-admin -- Controls --> secret_signing-key
  cloud_aws-admin -- Controls --> data_ledger
  cloud_aws-admin -- Controls --> storage_s3-statements
```
