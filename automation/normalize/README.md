# Telemetry Foundation (Phase 3)

The defensive backbone: raw logs from every source → one normalized schema → a queryable DuckDB table that the
detection runner reads. Batch, file-based, restartable — the right shape for an 8 GB host (no streaming SIEM).

```
range/data/logs/app.jsonl        (live: Kestrel API)          ┐
range/data/logs/access.log       (live: nginx)                │   automation/normalize/normalize.py
automation/normalize/samples/    (sysmon, cloudtrail, okta)   ├─►  ──► range/data/telemetry/events.jsonl
scripts/export-windows-telemetry.ps1 (REAL Windows host)      ┘        └► range/data/telemetry/telemetry.duckdb (events)
```

## Normalized event schema
One row per event, fields shared across all sources so detections stay portable:

| field | meaning |
|---|---|
| `ts` | ISO-8601 UTC timestamp |
| `source` | kestrel-api \| nginx \| sysmon \| cloudtrail \| identity |
| `event_type` | normalized action (login_success, process_create, GetSecretValue, …) |
| `actor` | user / principal / ARN |
| `src_ip` | source IP |
| `object_type`/`object_id`/`owner` | resource touched + who owns it (enables IDOR/BOLA detection) |
| `http_*` | method/path/status (app + nginx) |
| `host`/`process`/`parent_process`/`command_line` | endpoint fields (Sysmon) |
| `severity` | info \| low \| medium \| high \| critical |
| `technique` | MITRE ATT&CK id, when known at source |
| `details` | JSON blob of source-specific extras (queried via DuckDB `json_extract`) |

## Real endpoint telemetry (no VM)
`scripts/export-windows-telemetry.ps1` pulls **Sysmon** (`config/sysmon/sysmon-config.xml`) and **PowerShell
script-block** events from the builder's own Windows host into `samples/*.jsonl`, which the normalizer ingests exactly
like the bundled samples. The committed `samples/sysmon-sample.jsonl` lets the pipeline + tests run even before you
capture your own host telemetry.

## Run
```bash
python automation/normalize/normalize.py          # -> events.jsonl + telemetry.duckdb
# validated: 58 events across kestrel-api/sysmon/cloudtrail/identity
```
**Enterprise equivalent:** Winlogbeat/Vector/Fluent Bit → Elastic/Splunk/Sentinel index. Here: a Python normalizer →
DuckDB. Same idea (schema-on-write + a queryable store), a thousandth of the RAM.
