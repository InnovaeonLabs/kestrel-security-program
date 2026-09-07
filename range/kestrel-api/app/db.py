"""SQLite data layer for the Kestrel Pay range (synthetic data only).

SQLite is the default so the range runs in ~0 extra RAM on an 8 GB host.
A Postgres profile is available in docker-compose for the DB-heavy scenario,
but SQLite is sufficient to demonstrate SQLi/IDOR/enumeration telemetry.

Pure standard library (sqlite3) so seed.py can build the DB without FastAPI.
"""
from __future__ import annotations

import os
import random
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get("KESTREL_DB", os.path.join(os.path.dirname(__file__), "..", "data", "kestrel.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,               -- viewer | operator | admin
    password_hash TEXT NOT NULL,      -- synthetic
    mfa_enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS merchants (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL,   -- which Kestrel user "owns" this merchant
    country TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS payouts (
    id INTEGER PRIMARY KEY,
    merchant_id INTEGER NOT NULL,
    amount_cents INTEGER NOT NULL,
    currency TEXT DEFAULT 'USD',
    dest_bank_last4 TEXT NOT NULL,
    status TEXT DEFAULT 'pending',    -- pending | approved | paid
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY,
    merchant_id INTEGER NOT NULL,
    amount_cents INTEGER NOT NULL,
    payer_email TEXT NOT NULL,
    dest_bank_last4 TEXT NOT NULL,    -- BEC target: fraudulent change of this
    status TEXT DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY,
    merchant_id INTEGER NOT NULL,
    pan_token TEXT NOT NULL,          -- tokenized, synthetic (never a real PAN)
    brand TEXT NOT NULL,
    exp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    scope TEXT NOT NULL
);
"""

FIRST = ["ava", "noah", "mia", "liam", "zoe", "kai", "ivy", "leo", "ada", "raj", "sana", "omar"]
LAST = ["reyes", "kim", "patel", "nguyen", "cole", "diaz", "ford", "shah", "wu", "abbot"]
COUNTRIES = ["US", "GB", "DE", "CA", "NG", "BR", "IN", "AU"]
BRANDS = ["visa", "mastercard", "amex"]


@contextmanager
def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_and_seed(seed: int = 1337, reset: bool = True) -> dict:
    """Create schema and load synthetic data. Deterministic for reproducible demos."""
    rng = random.Random(seed)
    with connect() as conn:
        if reset:
            for t in ("api_tokens", "cards", "invoices", "payouts", "merchants", "users"):
                conn.execute(f"DROP TABLE IF EXISTS {t}")
        conn.executescript(SCHEMA)

        # Users: a few Kestrel staff. NOTE: password_hash is synthetic, not real.
        users = [
            (1, "svc_payouts", "svc_payouts@kestrelpay.example", "operator", "synthetic$hash", 0),
            (2, "ava.reyes",   "ava.reyes@kestrelpay.example",   "admin",    "synthetic$hash", 1),
            (3, "leo.kim",     "leo.kim@kestrelpay.example",     "operator", "synthetic$hash", 1),
            (4, "ivy.shah",    "ivy.shah@kestrelpay.example",    "viewer",   "synthetic$hash", 1),
        ]
        conn.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", users)

        # Merchants owned by different users -> enables IDOR (view a payout you don't own).
        for mid in range(1, 41):
            owner = rng.choice([2, 3, 4])
            conn.execute("INSERT INTO merchants VALUES (?,?,?,?,?)",
                         (mid, f"{rng.choice(FIRST).title()} {rng.choice(LAST).title()} LLC",
                          owner, rng.choice(COUNTRIES), rng.randint(0, 100)))

        # Payouts (the money). Some large -> fraud-worthy.
        pid = 1
        for mid in range(1, 41):
            for _ in range(rng.randint(1, 4)):
                amt = rng.choice([1299, 4900, 25000, 120000, 999900])
                conn.execute("INSERT INTO payouts VALUES (?,?,?,?,?,?,?)",
                             (pid, mid, amt, "USD", f"{rng.randint(1000,9999)}",
                              rng.choice(["pending", "approved", "paid"]),
                              "2026-08-%02dT%02d:00:00Z" % (rng.randint(1, 28), rng.randint(0, 23))))
                pid += 1

        # Invoices (BEC target), cards (tokenized), api tokens.
        for iid in range(1, 61):
            mid = rng.randint(1, 40)
            conn.execute("INSERT INTO invoices VALUES (?,?,?,?,?,?)",
                         (iid, mid, rng.choice([5000, 25000, 250000]),
                          f"{rng.choice(FIRST)}@buyer.example", f"{rng.randint(1000,9999)}", "open"))
        for cid in range(1, 81):
            conn.execute("INSERT INTO cards VALUES (?,?,?,?,?)",
                         (cid, rng.randint(1, 40), f"tok_{rng.randint(10**9, 10**10)}",
                          rng.choice(BRANDS), "12/29"))
        conn.execute("INSERT INTO api_tokens VALUES (?,?,?)",
                     ("kp_live_5f3a9c2b7e1d", 1, "payouts:write"))  # planted 'live' token (lab)
        return {"db": DB_PATH, "users": len(users), "payouts": pid - 1}


if __name__ == "__main__":
    print(init_and_seed())
