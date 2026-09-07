"""Telemetry normalizer — the heart of the 'telemetry-as-data' pipeline.

Reads raw logs from every source (app, nginx, Sysmon, CloudTrail, identity/Okta),
maps each into ONE normalized schema, writes a unified events.jsonl, and (if
duckdb is installed) loads them into a queryable `events` table that the Sigma
detection runner queries.

Design goals for an 8 GB host:
  * pure-stdlib parsing (duckdb is optional; pipeline still works without it)
  * batch, file-based, restartable, no daemon

Usage:
  python automation/normalize/normalize.py            # normalize -> events.jsonl (+duckdb if available)
  python automation/normalize/normalize.py --print 5  # also print first N normalized events
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW_LOG_DIR = os.environ.get("KESTREL_LOG_DIR", os.path.join(ROOT, "range", "data", "logs"))
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "samples")
OUT_DIR = os.path.join(ROOT, "range", "data", "telemetry")
OUT_JSONL = os.path.join(OUT_DIR, "events.jsonl")
DUCKDB_PATH = os.path.join(OUT_DIR, "telemetry.duckdb")

FIELDS = ["ts", "source", "event_id", "event_type", "action", "outcome", "actor",
          "src_ip", "user_agent", "session_id", "http_method", "http_path",
          "http_status", "object_type", "object_id", "owner", "severity",
          "technique", "host", "process", "parent_process", "command_line",
          "details"]


def _blank() -> dict:
    e = {k: "-" for k in FIELDS}
    e["http_status"] = 0
    e["details"] = {}
    e["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return e


# ---------- per-source parsers ----------
def parse_app(line: str) -> dict | None:
    """kestrel-api already emits the normalized schema; just fill missing keys."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    e = _blank()
    e.update({k: rec.get(k, e[k]) for k in FIELDS if k in rec})
    e["source"] = rec.get("source", "kestrel-api")
    e["details"] = rec.get("details", {})
    return e


NGINX_RE = re.compile(
    r'(?P<ip>\S+) - \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d+) (?P<bytes>\d+) "(?P<ua>[^"]*)"')


def parse_nginx(line: str) -> dict | None:
    m = NGINX_RE.search(line)
    if not m:
        return None
    e = _blank()
    e.update(source="nginx", event_type="http_request", action=m["method"],
             ts=m["ts"], src_ip=m["ip"], user_agent=m["ua"], http_method=m["method"],
             http_path=m["path"], http_status=int(m["status"]), severity="info",
             technique="T1190", details={"bytes": int(m["bytes"])})
    return e


SYSMON_EVENT_MAP = {
    1: ("process_create", "T1059"), 3: ("network_connect", "T1071"),
    7: ("image_load", "T1055"), 11: ("file_create", "T1105"),
    13: ("registry_set", "T1547"), 22: ("dns_query", "T1071.004"),
}


def parse_sysmon(line: str) -> dict | None:
    """Sysmon exported as JSON (see scripts/export-windows-telemetry.ps1)."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    eid = int(rec.get("EventID", rec.get("Id", 0)))
    etype, tech = SYSMON_EVENT_MAP.get(eid, (f"sysmon_{eid}", "-"))
    e = _blank()
    e.update(source="sysmon", event_type=etype, technique=tech,
             ts=rec.get("UtcTime", rec.get("TimeCreated", e["ts"])),
             host=rec.get("Computer", "-"), actor=rec.get("User", "-"),
             process=rec.get("Image", "-"), parent_process=rec.get("ParentImage", "-"),
             command_line=rec.get("CommandLine", "-"),
             src_ip=rec.get("DestinationIp", "-"), severity="info", details=rec)
    return e


def parse_cloudtrail(rec: dict) -> dict:
    e = _blank()
    ui = rec.get("userIdentity", {})
    e.update(source="cloudtrail", event_type=rec.get("eventName", "-"),
             action=rec.get("eventName", "-"), ts=rec.get("eventTime", e["ts"]),
             actor=ui.get("arn", ui.get("userName", "-")),
             src_ip=rec.get("sourceIPAddress", "-"),
             user_agent=rec.get("userAgent", "-"),
             outcome="failure" if rec.get("errorCode") else "success",
             severity="info", technique="T1078.004",
             details={"eventSource": rec.get("eventSource"),
                      "requestParameters": rec.get("requestParameters"),
                      # flattened scalar so detections can substring-match nested params
                      "request_json": json.dumps(rec.get("requestParameters", {}), separators=(",", ":")),
                      "errorCode": rec.get("errorCode")})
    return e


def parse_identity(rec: dict) -> dict:
    """Okta/Entra-style sign-in event (sample)."""
    e = _blank()
    e.update(source="identity", event_type=rec.get("eventType", "-"),
             action=rec.get("eventType", "-"), ts=rec.get("published", e["ts"]),
             actor=rec.get("actor", "-"), src_ip=rec.get("ip", "-"),
             user_agent=rec.get("userAgent", "-"),
             outcome=rec.get("outcome", "success"), severity="info",
             technique=rec.get("technique", "T1078"),
             details={k: rec.get(k) for k in ("city", "country", "mfa", "reason") if k in rec})
    return e


# ---------- driver ----------
def normalize_all() -> list[dict]:
    events: list[dict] = []
    # 1) live app + nginx logs from the running range
    for path in glob.glob(os.path.join(RAW_LOG_DIR, "app.jsonl")):
        with open(path, encoding="utf-8") as fh:
            events += [e for e in (parse_app(l) for l in fh) if e]
    for path in glob.glob(os.path.join(RAW_LOG_DIR, "access.log")):
        with open(path, encoding="utf-8") as fh:
            events += [e for e in (parse_nginx(l) for l in fh) if e]
    # 2) sample / scenario sources (sysmon, cloudtrail, identity, extra nginx/app)
    for path in glob.glob(os.path.join(SAMPLE_DIR, "*.jsonl")):
        base = os.path.basename(path)
        parser = (parse_sysmon if "sysmon" in base else
                  parse_nginx if "nginx" in base else parse_app)
        with open(path, encoding="utf-8") as fh:
            events += [e for e in (parser(l) for l in fh) if e]
    for path in glob.glob(os.path.join(SAMPLE_DIR, "cloudtrail*.json")):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        events += [parse_cloudtrail(r) for r in data.get("Records", data if isinstance(data, list) else [])]
    for path in glob.glob(os.path.join(SAMPLE_DIR, "identity*.json")):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        events += [parse_identity(r) for r in (data if isinstance(data, list) else [data])]
    events.sort(key=lambda e: e.get("ts", ""))
    return events


def write_jsonl(events: list[dict]) -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_JSONL, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, separators=(",", ":")) + "\n")


def load_duckdb(events: list[dict]) -> str | None:
    try:
        import duckdb
    except ImportError:
        return None
    con = duckdb.connect(DUCKDB_PATH)
    con.execute("DROP TABLE IF EXISTS events")
    # Flatten details to JSON text so Sigma-compiled SQL can json_extract it.
    con.execute("CREATE TABLE events (" + ", ".join(
        f"{f} JSON" if f == "details" else
        f"{f} INTEGER" if f == "http_status" else f"{f} VARCHAR"
        for f in FIELDS) + ")")
    rows = [[json.dumps(e["details"]) if f == "details" else e.get(f) for f in FIELDS] for e in events]
    con.executemany("INSERT INTO events VALUES (" + ",".join("?" * len(FIELDS)) + ")", rows)
    con.close()
    return DUCKDB_PATH


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--print", type=int, default=0, metavar="N")
    args = ap.parse_args()
    events = normalize_all()
    write_jsonl(events)
    db = load_duckdb(events)
    by_source: dict[str, int] = {}
    for e in events:
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1
    print(f"normalized {len(events)} events -> {OUT_JSONL}")
    print(f"by source: {by_source}")
    print(f"duckdb: {db or 'not installed (jsonl only) — run: pip install duckdb'}")
    for e in events[: args.print]:
        print(json.dumps({k: e[k] for k in ("ts", "source", "event_type", "actor", "severity")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
