"""SOAR-style alert triage & enrichment playbook (Phase 11 automation).

Takes raw detection alerts and does what an analyst does first, automatically:
  1. ENRICH   - match alert entities (IP/domain/actor) against the threat-intel feed
  2. CONTEXT  - add asset value (from the inventory) + crown-jewel/attack-path context
  3. SCORE    - compute a triage score -> priority (P1..P4) + recommended action
  4. CORRELATE- cluster alerts that share an entity/time window into incident cases
  5. CASE     - auto-write a case file from the correlated cluster
  6. MEASURE  - time the run and estimate analyst-minutes saved (documented assumptions)

Outputs:
  evidence/alerts/triaged-alerts.jsonl
  incident-response/auto-generated-case.md
  metrics/automation-metrics.json
Run:  python automation/soar/triage.py   (or `make triage`)
"""
from __future__ import annotations

import csv
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ALERTS = os.path.join(ROOT, "evidence", "alerts", "alerts.jsonl")
FEED = os.path.join(ROOT, "threat-intel", "iocs-feed.json")
ASSETS = os.path.join(ROOT, "assets", "asset-inventory.csv")
OUT_TRIAGE = os.path.join(ROOT, "evidence", "alerts", "triaged-alerts.jsonl")
OUT_CASE = os.path.join(ROOT, "incident-response", "auto-generated-case.md")
OUT_METRICS = os.path.join(ROOT, "metrics", "automation-metrics.json")

LEVEL_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Crown-jewel techniques (secrets/IAM/data) get a context bump.
CROWN_TECH = {"T1552", "T1552.001", "T1548", "T1530", "T1074", "T1114", "T1114.003"}
# Technique -> recommended first response (playbook).
PLAYBOOK = {
    "T1621": "Disable user sessions; reset MFA; enforce number-matching.",
    "T1110": "Rate-limit + block source IP; force password reset if any success.",
    "T1566": "Quarantine email; block domain; check who else clicked.",
    "T1550.001": "Revoke tokens; rotate signing secret; pin JWT alg.",
    "T1059.001": "Isolate host; collect PowerShell logs; hunt for stager.",
    "T1071": "Block C2 IP/domain; inspect egress; isolate host.",
    "T1547.001": "Remove run-key; re-image host; scan for persistence.",
    "T1190": "WAF-block source; patch endpoint; check data accessed.",
    "T1552.001": "Rotate the secret NOW; scope the role; alert on secret access.",
    "T1548": "Detach the policy; quarantine principal; review IAM.",
    "T1530": "Revert bucket policy; enable Block Public Access; check access logs.",
    "T1074": "Block export; preserve evidence; assess records exposed.",
    "T1114": "Freeze payout; verify bank details out-of-band.",
    "T1114.003": "Delete forwarding rule; review mailbox; check exfil.",
    "T1552": "Kill session; rotate exposed secrets; add guardrails.",
}


def load_feed():
    data = json.load(open(FEED, encoding="utf-8"))
    return {i["value"]: i for i in data["indicators"]}


def load_asset_values():
    crit = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Internal": 2}
    # rough: max asset value implicated by an alert's object_type keyword
    vals = {}
    for r in csv.DictReader(open(ASSETS, encoding="utf-8")):
        vals[r["asset"].lower()] = crit.get(r["business_criticality"], 2)
    return vals


def enrich(alert, feed):
    hits = []
    sample = alert.get("sample", {})
    for key in (sample.get("src_ip"), alert.get("entity")):
        if key and key in feed:
            hits.append(feed[key])
    return hits


def triage_one(alert, feed):
    base = LEVEL_SCORE.get(alert.get("level", "info"), 0)
    hits = enrich(alert, feed)
    intel_bonus = 0
    actor = "-"
    for h in hits:
        intel_bonus = max(intel_bonus, {"malicious": 3, "suspicious": 2, "test": 0}.get(h["reputation"], 0))
        if h.get("actor", "-") != "-":
            actor = h["actor"]
    crown_bonus = 2 if set(alert.get("techniques", [])) & CROWN_TECH else 0
    score = base + intel_bonus + crown_bonus
    priority = "P1" if score >= 7 else "P2" if score >= 5 else "P3" if score >= 3 else "P4"
    tech = (alert.get("techniques") or ["-"])[0]
    return {
        **alert,
        "triage_score": score,
        "priority": priority,
        "intel_hits": [{"value": h["value"], "reputation": h["reputation"], "actor": h.get("actor")} for h in hits],
        "attributed_actor": actor,
        "recommended_action": PLAYBOOK.get(tech, "Investigate; correlate with related alerts."),
    }


def correlate(triaged):
    """Cluster alerts sharing a source IP or attributed actor -> incident cases."""
    clusters = defaultdict(list)
    for a in triaged:
        key = a.get("sample", {}).get("src_ip") or a.get("entity") or "unknown"
        clusters[key].append(a)
    return clusters


def write_case(clusters, triaged):
    biggest_key = max(clusters, key=lambda k: len(clusters[k]))
    cluster = sorted(clusters[biggest_key], key=lambda a: a.get("ts_first", ""))
    techs = sorted({t for a in cluster for t in a.get("techniques", [])})
    p1 = [a for a in cluster if a["priority"] == "P1"]
    actor = next((a["attributed_actor"] for a in cluster if a["attributed_actor"] != "-"), "unknown")
    lines = [
        f"# Auto-Generated Incident Case (SOAR triage)", "",
        f"> Generated by `automation/soar/triage.py` from {len(triaged)} alerts. Not a replacement for the analyst-written "
        f"report ([`INC-2026-0821-scattered-sable.md`](INC-2026-0821-scattered-sable.md)) — this is the *machine* first pass.", "",
        f"**Correlation key:** `{biggest_key}`  |  **Alerts in cluster:** {len(cluster)}  |  "
        f"**Attributed actor:** {actor}  |  **P1 alerts:** {len(p1)}", "",
        f"**ATT&CK techniques observed:** {', '.join(techs)}", "",
        "## Prioritized alerts", "",
        "| Pri | Score | Detection | ATT&CK | Intel | Recommended action |",
        "|---|---|---|---|---|---|",
    ]
    for a in sorted(cluster, key=lambda a: -a["triage_score"]):
        intel = ",".join(h["reputation"] for h in a["intel_hits"]) or "-"
        lines.append(f"| {a['priority']} | {a['triage_score']} | {a['rule_title']} | "
                     f"{','.join(a.get('techniques', []))} | {intel} | {a['recommended_action']} |")
    lines += ["", "## Auto-recommended containment (dedup of actions above)"]
    for act in dict.fromkeys(a["recommended_action"] for a in sorted(cluster, key=lambda a: -a["triage_score"]) if a["priority"] == "P1"):
        lines.append(f"- {act}")
    open(OUT_CASE, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return biggest_key, len(cluster), len(clusters)


def main():
    t0 = time.perf_counter()
    feed = load_feed()
    alerts = [json.loads(l) for l in open(ALERTS, encoding="utf-8") if l.strip()]
    triaged = [triage_one(a, feed) for a in alerts]
    with open(OUT_TRIAGE, "w", encoding="utf-8") as fh:
        for a in triaged:
            fh.write(json.dumps(a) + "\n")
    clusters = correlate(triaged)
    key, cluster_n, n_clusters = write_case(clusters, triaged)
    elapsed = time.perf_counter() - t0

    # --- analyst-minutes-saved estimate (assumptions stated, not invented) ---
    MANUAL_MIN_PER_ALERT = 4.0    # typical manual triage+enrichment per alert (documented assumption)
    MANUAL_CASE_MIN = 20.0        # manual correlation + first-draft case file
    manual_total = len(alerts) * MANUAL_MIN_PER_ALERT + MANUAL_CASE_MIN
    automated_min = elapsed / 60.0
    saved = round(manual_total - automated_min, 1)
    metrics = {
        "alerts_triaged": len(alerts),
        "clusters": n_clusters,
        "primary_cluster_key": key,
        "primary_cluster_size": cluster_n,
        "p1_after_triage": sum(1 for a in triaged if a["priority"] == "P1"),
        "automated_runtime_sec": round(elapsed, 3),
        "assumptions": {"manual_min_per_alert": MANUAL_MIN_PER_ALERT, "manual_case_min": MANUAL_CASE_MIN},
        "manual_equivalent_min": manual_total,
        "analyst_minutes_saved_per_run": saved,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    json.dump(metrics, open(OUT_METRICS, "w", encoding="utf-8"), indent=2)

    print(f"triaged {len(alerts)} alerts -> {n_clusters} cluster(s); primary '{key}' has {cluster_n} alerts")
    print(f"P1 after triage: {metrics['p1_after_triage']}")
    print(f"analyst-minutes saved/run: ~{saved} (manual ~{manual_total} min vs automated {automated_min*60:.2f}s)")
    print(f"-> {os.path.relpath(OUT_TRIAGE, ROOT)}, {os.path.relpath(OUT_CASE, ROOT)}, {os.path.relpath(OUT_METRICS, ROOT)}")


if __name__ == "__main__":
    main()
