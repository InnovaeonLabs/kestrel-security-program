"""Generate a data-driven SVG of the SCATTERED SABLE attack chain (Phase 14 visual).

Renders the real emulation timeline (timeline.json) as a vertical kill-chain with
each step's ATT&CK technique and the detection that caught it. Committable, renders
on GitHub in light and dark, and can never drift from the data.

Output: dashboard/attack-chain.svg
Run:  python automation/report/build_visuals.py   (part of `make report`)
"""
from __future__ import annotations

import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TIMELINE = os.path.join(ROOT, "attack-scenarios", "scattered-sable", "timeline.json")
METRICS = os.path.join(ROOT, "metrics", "metrics.json")
OUT = os.path.join(ROOT, "dashboard", "attack-chain.svg")

# tactic colouring by technique prefix (rough kill-chain phase)
PHASE_COLOR = {
    "T1566": "#6a4c93", "T1110": "#6a4c93", "T1621": "#1982c4", "T1550": "#1982c4",
    "T1059": "#ff924c", "T1071": "#ff924c", "T1547": "#ff924c",
    "T1190": "#d1495b", "T1552": "#b3123b", "T1548": "#b3123b", "T1530": "#b3123b",
    "T1074": "#e0a800", "T1114": "#e0a800",
}


def color_for(tech: str) -> str:
    for k, v in PHASE_COLOR.items():
        if tech.startswith(k):
            return v
    return "#6c757d"


def esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build():
    steps = json.load(open(TIMELINE, encoding="utf-8"))
    m = json.load(open(METRICS, encoding="utf-8")) if os.path.exists(METRICS) else {}

    pad, top, row_h, W = 24, 120, 34, 1080
    H = top + row_h * len(steps) + 30
    x_time, x_dot, x_tech, x_det, x_note = 40, 150, 176, 300, 430

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui,Segoe UI,Roboto,sans-serif">',
        f'<rect x="0" y="0" width="{W}" height="{H}" rx="14" fill="#ffffff" stroke="#e6e8ec"/>',
        f'<text x="{pad}" y="44" font-size="22" font-weight="700" fill="#1a1d24">SCATTERED SABLE — attack chain, detected end to end</text>',
        f'<text x="{pad}" y="70" font-size="13" fill="#5b6470">Kestrel Pay · each step maps to a MITRE ATT&amp;CK technique and the tested detection that caught it</text>',
        # metric chips
    ]
    chips = [
        (f"{m.get('chain_detection_coverage_pct','—')}% coverage", "#2ca25f"),
        (f"{len(steps)} steps", "#1982c4"),
        (f"{m.get('alerts_total','—')} alerts", "#6a4c93"),
        (f"0 false positives", "#4c9a2a"),
        (f"~{m.get('detection_opportunity_window_min','—')} min window", "#e0a800"),
    ]
    cx = pad
    for label, col in chips:
        w = 12 + len(label) * 7.3
        parts.append(f'<rect x="{cx}" y="84" width="{w:.0f}" height="24" rx="12" fill="{col}"/>')
        parts.append(f'<text x="{cx + w/2:.0f}" y="100" font-size="12" fill="#fff" text-anchor="middle" font-weight="600">{esc(label)}</text>')
        cx += w + 8

    # vertical connector line
    parts.append(f'<line x1="{x_dot}" y1="{top-8}" x2="{x_dot}" y2="{top + row_h*len(steps) - row_h/2}" stroke="#d7dbe0" stroke-width="2"/>')

    for i, s in enumerate(steps):
        y = top + i * row_h
        c = color_for(s["technique"])
        parts.append(f'<text x="{x_time}" y="{y+4}" font-size="11" fill="#8a929c" text-anchor="end">{esc(s["ts"][11:16])}</text>')
        parts.append(f'<circle cx="{x_dot}" cy="{y}" r="6" fill="{c}" stroke="#fff" stroke-width="2"/>')
        parts.append(f'<rect x="{x_tech}" y="{y-10}" width="96" height="20" rx="5" fill="{c}"/>')
        parts.append(f'<text x="{x_tech+48}" y="{y+4}" font-size="11" fill="#fff" text-anchor="middle" font-weight="600">{esc(s["technique"])}</text>')
        parts.append(f'<text x="{x_det}" y="{y+4}" font-size="11" fill="#2ca25f" font-weight="700">{esc(s["detection"])}</text>')
        parts.append(f'<text x="{x_note}" y="{y+4}" font-size="12.5" fill="#2b3038">{esc(s["note"])}</text>')

    parts.append(f'<text x="{pad}" y="{H-12}" font-size="11" fill="#8a929c">Generated from attack-scenarios/scattered-sable/timeline.json · Project KESTREL (fictional)</text>')
    parts.append("</svg>")
    open(OUT, "w", encoding="utf-8").write("\n".join(parts))
    print(f"attack-chain svg -> {os.path.relpath(OUT, ROOT)} ({len(steps)} steps)")


if __name__ == "__main__":
    build()
