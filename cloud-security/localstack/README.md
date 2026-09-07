# OPTIONAL — Live Cloud Scenario (LocalStack)

The default cloud path in this project is **static** (Terraform + Checkov + a CloudTrail sample), which needs ~0 extra
RAM and is what the CI and reports use. This folder adds an **optional live** path for anyone with headroom (~1 GB RAM):
run the same misconfig + attack against **LocalStack** (a free local AWS emulator) and let the detections fire on
**live-confirmed** state.

> Not run in this build by design (the lab host is 8 GB and the project avoids long-running servers). All scripts are
> syntax-checked and ready to run on a machine with the prereqs.

## Prereqs
```bash
pip install awscli-local boto3          # awslocal + boto3
docker --version                         # Docker running
```

## Run (one shot)
```bash
bash cloud-security/localstack/run-scenario.sh
# tear down when done:
docker compose -f cloud-security/localstack/docker-compose.localstack.yml down
```
This will: start LocalStack → `setup.sh` (create the misconfigured bucket/role/user/secret) →
`attack.sh` (read the signing secret, attach AdministratorAccess, make the bucket public) →
`collect.py` (query LocalStack to **confirm** the misconfig and emit CloudTrail-shaped telemetry) →
normalize + run detections → **KP-0030 / KP-0031 / KP-0032 fire on live data.**

## Why it's optional (the tradeoff, stated)
| | Static path (default) | Live path (this folder) |
|---|---|---|
| RAM | ~0 | ~1 GB |
| Fidelity | IaC + sample events | real API calls + real state |
| CI-friendly | yes | no (needs Docker service) |
| When to use | always | when demonstrating a live cloud attack + detection |

Same three detections, same ATT&CK techniques (T1552.001 / T1548 / T1530) — just proven against a live emulator instead
of a sample. **Enterprise equivalent:** run against a real (sandbox) AWS account with GuardDuty/Config.
