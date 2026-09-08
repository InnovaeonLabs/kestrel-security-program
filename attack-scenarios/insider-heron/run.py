"""HOLLOW HERON — insider data-theft scenario (benign emulation).

A DIFFERENT threat model from SCATTERED SABLE: no external compromise. A trusted
internal user (`ivy.shah`, a viewer) abuses *legitimate* access to quietly bulk-read
customer records off-hours and exfiltrate them to personal cloud storage. Tests
insider-risk detection (volume + timing + destination), which volume-blind and
external-IP-based rules miss.

Chain -> ATT&CK -> detection:
  1 Off-hours login (legit creds)              T1078        -> (context)
  2 Bulk read of customer records off-hours    T1074        -> KP-0050
  3 Mass export                                 T1074        -> KP-0014
  4 Upload to personal cloud (exfil)            T1567.002    -> KP-0051

Usage: python attack-scenarios/insider-heron/run.py
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

ACTOR = "ivy.shah"          # a viewer who should not be bulk-reading customer data
OFFICE_IP = "203.0.113.11"  # legitimate office IP — NOT an external attacker IP
TIMELINE = []


def rec(step, tech, det, note):
    TIMELINE.append({"step": step, "technique": tech, "detection": det, "note": note})


def run():
    telemetry.emit("login_success", outcome="success", actor=ACTOR, src_ip=OFFICE_IP,
                   severity="info", technique="T1078", role="viewer", off_hours=True, hour="02:14")
    rec(1, "T1078", "-", "Off-hours login with legitimate credentials (02:14)")

    for i in range(15):  # bulk read of customer/card records, authorized but abnormal
        telemetry.emit("object_access", action="read_card", outcome="success", actor=ACTOR,
                       src_ip=OFFICE_IP, object_type="card", object_id=str(100 + i), owner="4",
                       severity="low", technique="T1074", authz="ok", off_hours=True)
    rec(2, "T1074", "KP-0050", "Read 15 customer/card records off-hours (legit authz)")

    telemetry.emit("bulk_export", outcome="success", actor=ACTOR, src_ip=OFFICE_IP,
                   object_type="cards", severity="high", technique="T1074", record_count=120,
                   off_hours=True)
    rec(3, "T1074", "KP-0014", "Bulk export of 120 customer records")

    telemetry.emit("data_upload_external", outcome="success", actor=ACTOR, src_ip=OFFICE_IP,
                   severity="high", technique="T1567.002", external=True,
                   destination="personal-dropbox.example", bytes=48213000)
    rec(4, "T1567.002", "KP-0051", "Uploaded export to personal cloud (personal-dropbox.example)")

    out = os.path.join(os.path.dirname(__file__), "timeline.json")
    json.dump(TIMELINE, open(out, "w", encoding="utf-8"), indent=2)
    print(f"HOLLOW HERON: emitted {len(TIMELINE)} steps -> {telemetry.LOG_FILE}")
    print("next: python automation/normalize/normalize.py && python automation/detect/run_sigma.py")


if __name__ == "__main__":
    run()
