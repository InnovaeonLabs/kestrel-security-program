# DFIR Investigation Notes — INC-2026-0821 (SCATTERED SABLE)

**Evidence store:** `range/data/telemetry/telemetry.duckdb` (normalized events), `evidence/alerts/alerts.jsonl`.
Investigation is reproducible: `make emulate && make detect`, then the DuckDB queries below.

## Hypotheses tested
- **H1 (accepted):** A single external actor drove the whole chain — same IP (45.77.0.10) + actor (leo.kim) links
  identity → endpoint → API → cloud events within one hour.
- **H2 (rejected):** Independent/benign admin activity — ruled out by MFA denials from a foreign geo immediately before
  the "successful" login, plus encoded-PowerShell + C2 beacon on the same user's host.

## Pivots / correlation (DuckDB)
```sql
-- everything touching the attacker IP, in order
SELECT ts, source, event_type, actor, technique
FROM events WHERE src_ip = '45.77.0.10' ORDER BY ts;

-- endpoint execution chain on the victim host
SELECT ts, event_type, process, command_line
FROM events WHERE host = 'KP-LAPTOP-07' ORDER BY ts;

-- crown-jewel cloud actions by the assumed role
SELECT ts, event_type, json_extract_string(details,'$.request_json') AS params
FROM events WHERE source='cloudtrail' AND actor LIKE '%assumed-role%' ORDER BY ts;
```

## Artifacts & IOCs
Extracted set in [`iocs.csv`](iocs.csv). Key host artifacts: encoded PowerShell command line (EID1), run-key
`...\CurrentVersion\Run\Updater` (EID13), session-token file `kp_session.tok` (EID11), C2 to `cdn.sable-c2.example` /
`45.77.0.10` (EID22/EID3). Key cloud artifacts: `GetSecretValue(prod/payments/signing-key)`, `AttachUserPolicy
(AdministratorAccess)`, `PutBucketPolicy(Principal:*)` under one assumed-role session.

## Evidence preservation (lab vs enterprise)
- **Lab:** immutable copy of `events.jsonl` + alerts committed under `evidence/`; DuckDB is the working store.
- **Enterprise:** write-once log retention (e.g., object-lock S3), disk/memory images of KP-LAPTOP-07, CloudTrail in a
  separate logging account, documented chain of custody. Noted so the judgment is visible even though the lab can't do full imaging.

## Containment inputs handed to IR
Block IP/domain, disable identity + revoke tokens, isolate host, detach admin policy, revert bucket, rotate signing key
+ JWT secret, freeze invoice #42. Mapped to the report's §6.
