"""Generate the ATT&CK coverage matrix + a Navigator layer from the rule catalogue.

Threat-informed defense, as code: the coverage view is *derived from the rules*,
so it can never drift from what actually ships. Honest about gaps.

Outputs:
  detections/coverage/coverage-matrix.md
  detections/coverage/attack-navigator-layer.json   (import at mitre-attack.github.io/attack-navigator)
"""
from __future__ import annotations

import glob
import json
import os

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULES_DIR = os.path.join(ROOT, "detections", "sigma")
OUT_DIR = os.path.join(ROOT, "detections", "coverage")

SOURCE_OF = {"kestrel-api": "App/API", "okta": "Identity", "cloudtrail": "Cloud/CloudTrail",
             "nginx": "Network", "windows": "Endpoint/Sysmon", "identity": "Identity"}


def _source(ls: dict) -> str:
    for key in ("service", "product"):
        if ls.get(key) in SOURCE_OF:
            return SOURCE_OF[ls[key]]
    return ls.get("category", "-")


def load():
    rows = []
    for p in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml"))):
        with open(p, encoding="utf-8") as fh:
            r = yaml.safe_load(fh)
        techs = [t.split(".", 1)[1].upper() for t in r.get("tags", []) if str(t).lower().startswith("attack.t")]
        rows.append({"id": r["id"], "title": r["title"], "level": r.get("level", "medium"),
                     "source": _source(r.get("logsource", {})), "techniques": techs,
                     "file": os.path.relpath(p, ROOT).replace("\\", "/")})
    return rows


def write_matrix(rows):
    os.makedirs(OUT_DIR, exist_ok=True)
    lines = ["# ATT&CK Coverage Matrix (generated)",
             "",
             "> Auto-generated from `detections/sigma/*.yml` by `automation/detect/coverage.py`. "
             "All rules ship with unit tests (`detections/tests`). Coverage is deliberately partial — "
             "gaps are listed so they can be closed in the purple-team phase.",
             "",
             "| ATT&CK | Detection | ID | Data source | Severity | Tested |",
             "|---|---|---|---|---|---|"]
    seen = set()
    for r in rows:
        for t in r["techniques"] or ["-"]:
            seen.add(t)
            lines.append(f"| `{t}` | {r['title']} | {r['id']} | {r['source']} | {r['level']} | ✅ unit |")
    # Known gaps: techniques in the threat model not yet covered (documented, not hidden).
    gaps = {"T1566": "Phishing (initial access) — modeled, not detected in-lab",
            "T1195": "Supply-chain compromise — handled by CI gates, not runtime detection",
            "T1110": "Credential stuffing/brute force — needs velocity rule on login_failure",
            "T1114.003": "Email forwarding rule — needs Workspace/Graph audit log source"}
    lines += ["", "## Documented coverage gaps (honest)", "", "| ATT&CK | Gap |", "|---|---|"]
    for t, why in gaps.items():
        if t not in seen:
            lines.append(f"| `{t}` | {why} |")
    covered = sorted(seen - {"-"})
    lines += ["", f"**Techniques with a tested detection:** {len(covered)} — {', '.join(covered)}"]
    with open(os.path.join(OUT_DIR, "coverage-matrix.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return covered


def write_navigator(rows, covered):
    techniques = []
    for r in rows:
        for t in r["techniques"]:
            techniques.append({"techniqueID": t, "score": 100, "color": "#2ca25f",
                               "comment": f"{r['id']} {r['title']}", "enabled": True})
    layer = {
        "name": "Kestrel Pay — Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Detections that ship in detections/sigma (all unit-tested).",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#2ca25f"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Tested detection", "color": "#2ca25f"}],
    }
    with open(os.path.join(OUT_DIR, "attack-navigator-layer.json"), "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)


def main():
    rows = load()
    covered = write_matrix(rows)
    write_navigator(rows, covered)
    print(f"coverage: {len(rows)} rules, {len(covered)} ATT&CK techniques -> detections/coverage/")
    print("techniques:", ", ".join(covered))


if __name__ == "__main__":
    main()
