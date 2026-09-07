"""Structured security telemetry for the Kestrel Pay API.

Every security-relevant event is written as one JSON object per line (JSONL) to
KESTREL_LOG_DIR/app.jsonl. This is the *telemetry-as-data* source that the
detection pipeline (automation/normalize -> DuckDB -> Sigma) consumes.

Field names are chosen to line up with a normalized schema used across all log
sources (app, nginx, sysmon, cloudtrail, identity) so Sigma rules stay portable.
Pure standard library on purpose: the seeder can emit telemetry without FastAPI.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

LOG_DIR = os.environ.get("KESTREL_LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "data", "logs"))
LOG_FILE = os.path.join(LOG_DIR, "app.jsonl")

# Common normalized event schema (documented once, reused everywhere).
# ts, source, event_type, action, outcome, actor, src_ip, user_agent,
# session_id, http_method, http_path, http_status, object_type, object_id,
# owner, severity, technique (ATT&CK), details{}
SOURCE = "kestrel-api"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def emit(event_type: str, *, action: str = "", outcome: str = "success",
         actor: str = "-", src_ip: str = "-", user_agent: str = "-",
         session_id: str = "-", http_method: str = "-", http_path: str = "-",
         http_status: int = 0, object_type: str = "-", object_id: str = "-",
         owner: str = "-", severity: str = "info", technique: str = "-",
         **details) -> dict:
    """Write one normalized telemetry event and return it."""
    event = {
        "ts": _now(),
        "source": SOURCE,
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "action": action or event_type,
        "outcome": outcome,
        "actor": actor,
        "src_ip": src_ip,
        "user_agent": user_agent,
        "session_id": session_id,
        "http_method": http_method,
        "http_path": http_path,
        "http_status": http_status,
        "object_type": object_type,
        "object_id": object_id,
        "owner": owner,
        "severity": severity,
        "technique": technique,
        "details": details,
    }
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    except OSError as exc:  # never let telemetry take down the app
        print(f"[telemetry] write failed: {exc}", file=sys.stderr)
    return event
