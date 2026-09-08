"""SPLINTER VIPER — software supply-chain / CI-CD compromise (benign emulation).

A THIRD threat model: the attacker never touches prod directly — they poison the
pipeline. A leaked CI secret + a malicious dependency ride a build into production.
This is where the DevSecOps CI gates (gitleaks/Semgrep/Trivy/Checkov) earn their
keep, and it exercises a new telemetry source: `cicd`.

Chain -> ATT&CK -> detection:
  1 Secret committed / found in CI            T1552        -> KP-0060
  2 Malicious/vulnerable dependency added     T1195.002    -> KP-0061
  3 Unsigned build deployed to production      T1195/T1554  -> KP-0062

Usage: python attack-scenarios/supply-chain-viper/run.py
Then:  python automation/normalize/normalize.py && python automation/detect/run_sigma.py
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "range", "kestrel-api"))
os.environ.setdefault("KESTREL_LOG_DIR", os.path.join(ROOT, "range", "data", "logs"))
from app import telemetry  # noqa: E402

TIMELINE = []


def _rewrite_source_last(n, source):
    with open(telemetry.LOG_FILE, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    for i in range(max(0, len(lines) - n), len(lines)):
        obj = json.loads(lines[i]); obj["source"] = source
        lines[i] = json.dumps(obj, separators=(",", ":"))
    with open(telemetry.LOG_FILE, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def rec(step, tech, det, note):
    TIMELINE.append({"step": step, "technique": tech, "detection": det, "note": note})


def run():
    telemetry.emit("secret_scan_hit", outcome="success", actor="dev-bot", severity="high",
                   technique="T1552", rule="aws-access-key-id", file="services/config.py",
                   commit="9f2c1ab")
    _rewrite_source_last(1, "cicd")
    rec(1, "T1552", "KP-0060", "AWS key committed to services/config.py (gitleaks hit)")

    telemetry.emit("dependency_vuln", outcome="success", actor="dependabot", severity="high",
                   technique="T1195.002", package="leftpad-evil==1.3.3", advisory_severity="critical",
                   advisory="GHSA-lab-0001", note="typosquat with post-install hook")
    _rewrite_source_last(1, "cicd")
    rec(2, "T1195.002", "KP-0061", "Malicious dependency leftpad-evil==1.3.3 added")

    telemetry.emit("deploy_prod", outcome="success", actor="ci-runner", severity="critical",
                   technique="T1195", signed=False, commit="9f2c1ab", environment="production")
    _rewrite_source_last(1, "cicd")
    rec(3, "T1195", "KP-0062", "Unsigned build deployed to production")

    out = os.path.join(os.path.dirname(__file__), "timeline.json")
    json.dump(TIMELINE, open(out, "w", encoding="utf-8"), indent=2)
    print(f"SPLINTER VIPER: emitted {len(TIMELINE)} steps -> {telemetry.LOG_FILE}")
    print("next: python automation/normalize/normalize.py && python automation/detect/run_sigma.py")


if __name__ == "__main__":
    run()
