"""Detection-as-code engine (Sigma-subset -> DuckDB SQL).

Authoring format is genuine Sigma YAML (title/id/logsource/detection/condition/
level/tags). Rather than pull the full pySigma toolchain + a SQL backend (heavy,
and no off-the-shelf DuckDB backend), this is a purpose-built compiler for the
common Sigma subset PLUS a small temporal-aggregation extension for
threshold/velocity rules (MFA fatigue, IDOR enumeration).

  * Enterprise equivalent: pySigma + sigma-cli with a Splunk/Elastic backend.
  * Lab choice: ~250 lines, zero-daemon, runs the SAME rules against DuckDB.

Public API (also used by the unit tests):
  compile_where(rule)          -> SQL WHERE fragment
  run_rule_on_events(events, rule) -> list[alert dict]
  run_all(con) / main()

Supported per-selection:  field, field|contains, |startswith, |endswith, |re,
  |gte/|lte/|gt/|lt ; list value = OR ; list-of-maps = OR of ANDs ;
  dotted field 'details.x' -> json_extract_string.
Condition: and / or / not / parens, 'all of them', '1 of them',
  'all of sel*', '1 of sel*'.
Optional 'aggregation:' block: {group_by, timespan (e.g. 15m), threshold}.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
from datetime import datetime, timedelta

import duckdb
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULES_DIR = os.path.join(ROOT, "detections", "sigma")
DB_PATH = os.path.join(ROOT, "range", "data", "telemetry", "telemetry.duckdb")
ALERTS_OUT = os.path.join(ROOT, "evidence", "alerts", "alerts.jsonl")

COLUMNS = {"ts", "source", "event_id", "event_type", "action", "outcome", "actor",
           "src_ip", "user_agent", "session_id", "http_method", "http_path",
           "http_status", "object_type", "object_id", "owner", "severity",
           "technique", "host", "process", "parent_process", "command_line"}
ALIASES = {  # convenience Sigma-ish names -> normalized field
    "CommandLine": "command_line", "Image": "process", "ParentImage": "parent_process",
    "User": "actor", "TargetObject": "details.TargetObject",
    "TargetFilename": "details.TargetFilename", "QueryName": "details.QueryName",
    "EventName": "event_type", "eventName": "event_type",
}
LOGSOURCE_MAP = {  # (product,category,service) hints -> base SQL predicate
    ("", "", "kestrel-api"): "source='kestrel-api'",
    ("", "", "nginx"): "source='nginx'",
    ("", "", "cloudtrail"): "source='cloudtrail'",
    ("", "", "okta"): "source='identity'",
    ("identity", "", ""): "source='identity'",
    ("windows", "process_creation", ""): "source='sysmon' AND event_type='process_create'",
    ("windows", "registry_set", ""): "source='sysmon' AND event_type='registry_set'",
    ("windows", "network_connection", ""): "source='sysmon' AND event_type='network_connect'",
    ("windows", "dns_query", ""): "source='sysmon' AND event_type='dns_query'",
    ("windows", "file_event", ""): "source='sysmon' AND event_type='file_create'",
}


def _q(v) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def _col(field: str) -> str:
    field = ALIASES.get(field, field)
    if field.startswith("details."):
        return f"json_extract_string(details, '$.{field.split('.',1)[1]}')"
    if field in COLUMNS:
        return field
    return f"json_extract_string(details, '$.{field}')"  # unknown -> look in details


def _leaf(field_mod: str, value) -> str:
    parts = field_mod.split("|")
    field, mods = parts[0], parts[1:]
    col = _col(field)
    if isinstance(value, list) and "all" not in mods:
        return "(" + " OR ".join(_leaf("|".join([field] + [m for m in mods if m != "all"]), v)
                                 for v in value) + ")"
    if isinstance(value, list):  # |all -> AND
        return "(" + " AND ".join(_leaf(field + ("|" + "|".join(m for m in mods if m != "all") if len(mods) > 1 else ""), v)
                                  for v in value) + ")"
    if "contains" in mods:
        return f"{col} ILIKE {_q('%'+str(value)+'%')}"
    if "startswith" in mods:
        return f"{col} ILIKE {_q(str(value)+'%')}"
    if "endswith" in mods:
        return f"{col} ILIKE {_q('%'+str(value))}"
    if "re" in mods:
        return f"regexp_matches({col}, {_q(value)})"
    for m, op in (("gte", ">="), ("lte", "<="), ("gt", ">"), ("lt", "<")):
        if m in mods:
            return f"TRY_CAST({col} AS DOUBLE) {op} {float(value)}"
    if isinstance(value, bool):
        return f"lower({col}) = {_q(str(value).lower())}"
    return f"lower({col}) = lower({_q(value)})"


def _selection_sql(sel) -> str:
    if isinstance(sel, list):  # list of maps -> OR of ANDs
        return "(" + " OR ".join(_selection_sql(s) for s in sel) + ")"
    return "(" + " AND ".join(_leaf(k, v) for k, v in sel.items()) + ")"


def _logsource_pred(ls: dict) -> str:
    key = (ls.get("product", ""), ls.get("category", ""), ls.get("service", ""))
    if key in LOGSOURCE_MAP:
        return LOGSOURCE_MAP[key]
    # fall back on any single matching hint
    for (p, c, s), pred in LOGSOURCE_MAP.items():
        if (p and p == key[0]) or (c and c == key[1]) or (s and s == key[2]):
            return pred
    return "1=1"


def _condition_sql(condition: str, sel_sql: dict) -> str:
    names = list(sel_sql)
    non_cond = [n for n in names]

    def expand(m):
        kind, _, pat = m.group(1), m.group(2), m.group(3)
        pat = pat.strip()
        if pat == "them":
            chosen = non_cond
        else:
            pref = pat.rstrip("*")
            chosen = [n for n in non_cond if n.startswith(pref)]
        joiner = " AND " if kind == "all" else " OR "
        return "(" + joiner.join(chosen) + ")"

    expr = re.sub(r"\b(all|1|any)\s+(of)\s+(them|[A-Za-z0-9_]+\*?)", expand, condition)
    # tokenize identifiers (selection names) and operators
    out = []
    for tok in re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_]+", expr):
        low = tok.lower()
        if low in ("and", "or", "not"):
            out.append(low.upper())
        elif tok in ("(", ")"):
            out.append(tok)
        elif tok in sel_sql:
            out.append("(" + sel_sql[tok] + ")")
        else:
            out.append(tok)  # leave literals
    return " ".join(out) if out else "1=1"


def compile_where(rule: dict) -> str:
    det = rule["detection"]
    sels = {k: _selection_sql(v) for k, v in det.items() if k != "condition"}
    cond = _condition_sql(str(det.get("condition", "1 of them")), sels)
    base = _logsource_pred(rule.get("logsource", {}))
    return f"({base}) AND ({cond})"


def _parse_ts(s: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _timespan_seconds(s: str) -> int:
    m = re.match(r"(\d+)\s*([smhd])", str(s))
    if not m:
        return 0
    n, u = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[u]


def _aggregate(rows: list[dict], agg: dict) -> list[dict]:
    gb = agg["group_by"]
    span = _timespan_seconds(agg.get("timespan", "0m"))
    thresh = int(agg.get("threshold", 2))
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r.get(gb, "-"), []).append(r)
    hits = []
    for key, evs in groups.items():
        evs = sorted(evs, key=lambda e: e.get("ts", ""))
        if span == 0:
            if len(evs) >= thresh:
                hits.append((key, evs))
            continue
        i = 0
        for j in range(len(evs)):
            tj = _parse_ts(evs[j]["ts"])
            while i < j and tj and _parse_ts(evs[i]["ts"]) and (tj - _parse_ts(evs[i]["ts"])).total_seconds() > span:
                i += 1
            if j - i + 1 >= thresh:
                hits.append((key, evs[i:j + 1]))
                break
    return [{"entity": k, "events": e} for k, e in hits]


def _alert(rule: dict, events: list[dict], entity: str = "-") -> dict:
    tags = rule.get("tags", [])
    techniques = [t.split(".", 1)[1] if t.startswith("attack.t") else t
                  for t in tags if t.lower().startswith("attack.t")]
    techniques = [t.upper() for t in techniques]
    ev = events[0]
    return {
        "rule_id": rule.get("id", rule.get("title")),
        "rule_title": rule["title"],
        "level": rule.get("level", "medium"),
        "techniques": techniques or ([ev.get("technique")] if ev.get("technique", "-") != "-" else []),
        "source": rule.get("logsource", {}),
        "entity": entity if entity != "-" else ev.get("actor", "-"),
        "ts_first": events[0].get("ts"),
        "ts_last": events[-1].get("ts"),
        "count": len(events),
        "event_ids": [e.get("event_id") for e in events][:20],
        "sample": {k: ev.get(k) for k in ("ts", "source", "event_type", "actor", "src_ip",
                                          "http_path", "object_id", "command_line")},
    }


def run_rule(con: duckdb.DuckDBPyConnection, rule: dict) -> list[dict]:
    where = compile_where(rule)
    cur = con.execute(f"SELECT * FROM events WHERE {where} ORDER BY ts")
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    dicts = [dict(zip(cols, r)) for r in rows]
    for d in dicts:
        if isinstance(d.get("details"), str):
            try:
                d["details"] = json.loads(d["details"])
            except (ValueError, TypeError):
                pass
    agg = rule.get("aggregation")
    if agg:
        return [_alert(rule, g["events"], g["entity"]) for g in _aggregate(dicts, agg)]
    return [_alert(rule, [d]) for d in dicts]


def run_rule_on_events(events: list[dict], rule: dict) -> list[dict]:
    """In-memory helper for unit tests: load events into a temp DuckDB and run."""
    con = duckdb.connect(":memory:")
    fields = list(COLUMNS) + ["details"]
    con.execute("CREATE TABLE events (" + ", ".join(
        f"{f} JSON" if f == "details" else f"{f} INTEGER" if f == "http_status" else f"{f} VARCHAR"
        for f in fields) + ")")
    for e in events:
        vals = [json.dumps(e.get("details", {})) if f == "details" else e.get(f) for f in fields]
        con.execute("INSERT INTO events VALUES (" + ",".join("?" * len(fields)) + ")", vals)
    out = run_rule(con, rule)
    con.close()
    return out


def load_rules() -> list[dict]:
    rules = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        with open(path, encoding="utf-8") as fh:
            rule = yaml.safe_load(fh)
        rule["_path"] = os.path.relpath(path, ROOT)
        rules.append(rule)
    return rules


def run_all(con: duckdb.DuckDBPyConnection) -> tuple[list[dict], dict]:
    all_alerts, summary = [], {}
    for rule in load_rules():
        alerts = run_rule(con, rule)
        summary[rule["title"]] = len(alerts)
        all_alerts += alerts
    techniques = sorted({t for a in all_alerts for t in a["techniques"]})
    return all_alerts, {"by_rule": summary, "total_alerts": len(all_alerts),
                        "techniques_detected": techniques}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=DB_PATH)
    args = ap.parse_args()
    if not os.path.exists(args.db):
        print(f"[!] {args.db} not found — run automation/normalize/normalize.py first")
        return 1
    con = duckdb.connect(args.db)
    alerts, summary = run_all(con)
    os.makedirs(os.path.dirname(ALERTS_OUT), exist_ok=True)
    with open(ALERTS_OUT, "w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a) + "\n")
    print(f"=== {summary['total_alerts']} alerts from {len(summary['by_rule'])} rules -> {os.path.relpath(ALERTS_OUT, ROOT)}")
    for title, n in sorted(summary["by_rule"].items(), key=lambda kv: -kv[1]):
        flag = "  " if n else "  (silent) "
        print(f"{flag}{n:>3}  {title}")
    print(f"techniques detected: {', '.join(summary['techniques_detected'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
