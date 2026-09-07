"""Standalone seeder + benign-traffic telemetry generator (pure stdlib).

Runs WITHOUT FastAPI so it works as a light check and produces evidence:
  * builds the synthetic SQLite DB
  * emits a burst of *benign* baseline telemetry to KESTREL_LOG_DIR/app.jsonl

This baseline is what detections are tuned against (to measure false positives).
Usage:  python seed.py            (build DB + emit ~40 benign events)
"""
from __future__ import annotations

import random
import sys

from app import telemetry
from app.db import init_and_seed

BENIGN_UAS = ["KestrelSDK/1.4 (python)", "Mozilla/5.0 (Macintosh)", "KestrelSDK/1.4 (node)"]
BENIGN_USERS = ["ava.reyes", "leo.kim", "ivy.shah", "svc_payouts"]
OFFICE_IPS = ["203.0.113.10", "203.0.113.11", "198.51.100.7"]  # documentation ranges


def emit_benign(n: int = 40, seed: int = 7) -> int:
    rng = random.Random(seed)
    for _ in range(n):
        u = rng.choice(BENIGN_USERS)
        ip = rng.choice(OFFICE_IPS)
        ua = rng.choice(BENIGN_UAS)
        roll = rng.random()
        if roll < 0.4:
            telemetry.emit("login_success", outcome="success", actor=u, src_ip=ip,
                           user_agent=ua, technique="T1078", role="operator", mfa_used=True)
        elif roll < 0.7:
            telemetry.emit("object_access", action="read_payout", outcome="success", actor=u,
                           src_ip=ip, object_type="payout", object_id=str(rng.randint(1, 80)),
                           owner=str(rng.choice([2, 3, 4])), technique="T1190",
                           authz="ok", amount_cents=rng.choice([1299, 4900, 25000]))
        elif roll < 0.85:
            telemetry.emit("db_query", action="search", outcome="success", actor=u, src_ip=ip,
                           object_type="merchant", technique="T1190", sqli_suspected=False,
                           query="SELECT id,name,country FROM merchants WHERE name LIKE '%acme%'")
        else:
            telemetry.emit("copilot_query", outcome="success", actor="merchant-user", src_ip=ip)
    return n


if __name__ == "__main__":
    info = init_and_seed()
    count = emit_benign()
    print(f"seeded DB: {info}; emitted {count} benign telemetry events to {telemetry.LOG_FILE}")
