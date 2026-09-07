"""Generate the static security dashboard from real evidence (Phase 14).

Reads metrics.json, alerts.jsonl, attack-paths.json, the vuln register, and the
Checkov output, and renders a single self-contained, theme-aware HTML file:
  dashboard/index.html

No server, no build step, no JS deps — opens locally or on GitHub Pages.
Run:  make report   (python automation/report/build_report.py)
"""
from __future__ import annotations

import csv
import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _read_json(rel, default=None):
    p = os.path.join(ROOT, rel)
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else (default or {})


def _read_lines(rel):
    p = os.path.join(ROOT, rel)
    return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()] if os.path.exists(p) else []


def _checkov_failed():
    p = os.path.join(ROOT, "evidence", "logs", "checkov-run.txt")
    if not os.path.exists(p):
        return "—"
    m = re.findall(r"Failed checks:\s*(\d+)", open(p, encoding="utf-8", errors="ignore").read())
    return sum(int(x) for x in m) if m else "—"


def _vuln_stats():
    p = os.path.join(ROOT, "vulnerability-management", "register.csv")
    if not os.path.exists(p):
        return 0, 0
    rows = list(csv.DictReader(open(p, encoding="utf-8")))
    p1 = sum(1 for r in rows if r.get("priority") == "P1")
    return len(rows), p1


LEVEL_COLOR = {"critical": "#b3123b", "high": "#d1495b", "medium": "#e0a800", "low": "#4c9a2a", "info": "#6c757d"}


def build():
    m = _read_json("metrics/metrics.json")
    alerts = _read_lines("evidence/alerts/alerts.jsonl")
    paths = _read_json("identity/graph/attack-paths.json")
    vulns, p1 = _vuln_stats()
    checkov = _checkov_failed()

    tiles = [
        ("Chain detection coverage", f"{m.get('chain_detection_coverage_pct','—')}%", f"{len(m.get('techniques_detected',[]))} ATT&CK techniques"),
        ("Alerts on the intrusion", m.get("alerts_total", "—"), f"{m.get('rules_fired','—')}/{m.get('rules_total','—')} rules fired"),
        ("False positives (benign)", f"{m.get('false_positives_on_benign_baseline','—')}/{m.get('benign_baseline_events','—')}", "tuned on data"),
        ("Detection window", f"{m.get('detection_opportunity_window_min','—')} min", "before business impact"),
        ("Detection unit tests", f"{m.get('unit_tests','—').split()[0]} pass", "fires + silent"),
        ("Attack paths to crown jewels", f"{paths.get('total_paths_current','—')} → {paths.get('total_paths_target','—')}", f"{paths.get('attack_paths_eliminated','—')} eliminated"),
        ("Vulnerabilities", f"{vulns} ({p1} P1)", "risk-based priority"),
        ("IaC misconfigs (Checkov)", checkov, "static scan"),
    ]

    tile_html = "".join(
        f'<div class="tile"><div class="v">{v}</div><div class="k">{k}</div><div class="s">{s}</div></div>'
        for k, v, s in tiles)

    rows = ""
    for a in sorted(alerts, key=lambda a: a.get("ts_first", "")):
        lvl = a.get("level", "info")
        techs = ", ".join(a.get("techniques", []))
        rows += (f'<tr><td><span class="pill" style="background:{LEVEL_COLOR.get(lvl,"#6c757d")}">{lvl}</span></td>'
                 f'<td>{a.get("rule_title","")}</td><td class="mono">{techs}</td>'
                 f'<td class="mono">{a.get("entity","")}</td><td class="mono">{a.get("ts_first","")}</td>'
                 f'<td>{a.get("count",1)}</td></tr>')

    covered = ", ".join(m.get("techniques_detected", []))
    html = TEMPLATE.replace("{{TILES}}", tile_html).replace("{{ROWS}}", rows).replace("{{COVERED}}", covered)
    out = os.path.join(ROOT, "dashboard", "index.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "w", encoding="utf-8").write(html)
    print(f"dashboard -> {os.path.relpath(out, ROOT)} ({len(alerts)} alerts, {vulns} vulns)")


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Project KESTREL — Security Dashboard</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a1d24;--muted:#5b6470;--line:#e6e8ec;--accent:#2ca25f;--accent2:#2b6cb0}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e8eaed;--muted:#9aa4b0;--line:#262c34}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 20px}
h1{font-size:22px;margin:0 0 2px}.sub{color:var(--muted);margin:0 0 22px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-bottom:26px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.tile .v{font-size:26px;font-weight:700;color:var(--accent)}
.tile .k{font-weight:600;margin-top:4px}.tile .s{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:20px;overflow-x:auto}
h2{font-size:15px;margin:0 0 12px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}
.pill{color:#fff;padding:2px 8px;border-radius:999px;font-size:11px;text-transform:uppercase;letter-spacing:.03em}
.tag{display:inline-block;background:var(--line);border-radius:6px;padding:2px 8px;margin:2px;font-family:ui-monospace,monospace;font-size:12px}
.foot{color:var(--muted);font-size:12px;margin-top:8px}
</style></head><body><div class="wrap">
<h1>Project KESTREL — Security Dashboard</h1>
<p class="sub">Kestrel Pay · SCATTERED SABLE intrusion · generated from real evidence (metrics.json, alerts.jsonl, attack-paths.json)</p>
<div class="grid">{{TILES}}</div>
<div class="card"><h2>ATT&amp;CK techniques detected</h2><div>{{COVERED}}</div></div>
<div class="card"><h2>Alerts from the emulated intrusion</h2>
<table><thead><tr><th>Severity</th><th>Detection</th><th>ATT&amp;CK</th><th>Entity</th><th>First seen</th><th>#</th></tr></thead>
<tbody>{{ROWS}}</tbody></table>
<p class="foot">Rules are unit-tested (fires-on-malicious + silent-on-benign). App/API rules produce 0 alerts on the benign baseline.</p>
</div>
<p class="foot">Regenerate: <code>make report</code>. Independent portfolio project; "Kestrel Pay" is fictional.</p>
</div></body></html>"""


if __name__ == "__main__":
    build()
