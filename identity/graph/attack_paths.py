"""Identity / cloud attack-path analysis (BloodHound-lite) with networkx.

Models Kestrel Pay principals, hosts, roles, secrets and data as a directed graph
and finds paths from a realistic entry point (a phished engineer) to the crown
jewels. Compares CURRENT state (over-privileged) vs TARGET state (least-privilege)
and reports the number of attack paths ELIMINATED — a hard metric for the report.

Run:  python identity/graph/attack_paths.py
Outputs: attack-paths.json, attack-paths.md (with Mermaid), and prints before/after.
"""
from __future__ import annotations

import json
import os

import networkx as nx

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

CROWN_JEWELS = ["secret:signing-key", "cloud:aws-admin", "data:ledger"]
ENTRY = "user:leo.kim"

# (src, dst, relationship). Edges tagged 'risky' exist only because of a misconfig
# and are removed in the target state.
EDGES_CURRENT = [
    ("user:leo.kim", "host:KP-LAPTOP-07", "HasSession"),
    ("user:leo.kim", "group:engineers", "MemberOf"),
    ("group:engineers", "saas:github", "CanAccess"),
    ("saas:github", "cicd:actions", "Triggers"),
    ("cicd:actions", "role:deploy", "AssumesViaOIDC"),
    # risky: laptop can reach the task role via stolen creds / SSRF to IMDS
    ("host:KP-LAPTOP-07", "role:kestrel-api-task", "CanAssume(SSRF/creds)", "risky"),
    # risky: task role has wildcard admin
    ("role:kestrel-api-task", "cloud:aws-admin", "Admin*(wildcard)", "risky"),
    # risky: task role can read the signing key directly (no scoping)
    ("role:kestrel-api-task", "secret:signing-key", "CanRead(unscoped)", "risky"),
    ("cloud:aws-admin", "secret:signing-key", "Controls"),
    ("cloud:aws-admin", "data:ledger", "Controls"),
    ("cloud:aws-admin", "storage:s3-statements", "Controls"),
    ("role:deploy", "cloud:aws-admin", "AttachPolicy*(wildcard)", "risky"),
]
# Target state removes the 'risky' edges (least-privilege + guardrails).
def build(edges, drop_risky=False):
    g = nx.DiGraph()
    for e in edges:
        risky = len(e) == 4 and e[3] == "risky"
        if drop_risky and risky:
            continue
        g.add_edge(e[0], e[1], rel=e[2], risky=risky)
    return g


def paths_to_jewels(g):
    out = {}
    for jewel in CROWN_JEWELS:
        if jewel in g and nx.has_path(g, ENTRY, jewel):
            # all simple paths (bounded) from entry to the jewel
            out[jewel] = list(nx.all_simple_paths(g, ENTRY, jewel, cutoff=8))
        else:
            out[jewel] = []
    return out


def mermaid(g) -> str:
    lines = ["```mermaid", "flowchart LR"]
    for u, v, d in g.edges(data=True):
        style = "-. " + d["rel"] + " .->" if d.get("risky") else "-- " + d["rel"] + " -->"
        lines.append(f'  {u.replace(":","_")} {style} {v.replace(":","_")}')
    lines.append("```")
    return "\n".join(lines)


def main():
    g_now = build(EDGES_CURRENT, drop_risky=False)
    g_target = build(EDGES_CURRENT, drop_risky=True)
    now = paths_to_jewels(g_now)
    target = paths_to_jewels(g_target)

    n_now = sum(len(v) for v in now.values())
    n_target = sum(len(v) for v in target.values())

    result = {
        "entry": ENTRY,
        "crown_jewels": CROWN_JEWELS,
        "paths_current": {k: len(v) for k, v in now.items()},
        "paths_target": {k: len(v) for k, v in target.items()},
        "total_paths_current": n_now,
        "total_paths_target": n_target,
        "attack_paths_eliminated": n_now - n_target,
        "example_current_path_to_signing_key":
            (now["secret:signing-key"][0] if now["secret:signing-key"] else None),
    }
    json.dump(result, open(os.path.join(HERE, "attack-paths.json"), "w", encoding="utf-8"), indent=2)

    md = ["# Identity & Cloud Attack-Path Analysis", "",
          f"Entry point: **{ENTRY}** (phished engineer). Crown jewels: "
          f"{', '.join('`'+j+'`' for j in CROWN_JEWELS)}.", "",
          "## Result (computed)",
          f"- Attack paths to crown jewels — **current: {n_now}**, **target (least-privilege): {n_target}**",
          f"- **Attack paths eliminated: {n_now - n_target}**",
          "",
          "Example current path to the signing key:",
          "",
          "`" + " -> ".join(result["example_current_path_to_signing_key"] or []) + "`",
          "",
          "## What eliminates them",
          "- Scope `kestrel-api-task` to only the secrets/resources it needs (remove wildcard admin).",
          "- SCP guardrail denying `iam:Attach*` / `*:*` on the deploy path.",
          "- IMDSv2 + SSRF allow-list so a compromised laptop/app can't assume the task role.",
          "",
          "## Current-state graph (risky edges dashed)", "",
          mermaid(g_now)]
    open(os.path.join(HERE, "attack-paths.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")

    print(f"paths to crown jewels — current: {n_now}, target: {n_target}, "
          f"eliminated: {n_now - n_target}")
    for j in CROWN_JEWELS:
        print(f"  {j}: {len(now[j])} -> {len(target[j])}")


if __name__ == "__main__":
    main()
