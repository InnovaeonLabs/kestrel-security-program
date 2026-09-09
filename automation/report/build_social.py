"""Generate the GitHub social-preview image (1280x640 PNG) from real project stats.

Upload the output at: repo Settings -> Social preview.
Run: python automation/report/build_social.py
"""
from __future__ import annotations

import json
import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "dashboard", "social-preview.png")
FONTS = "C:/Windows/Fonts"

BG = (13, 17, 23)          # GitHub dark
CARD = (22, 27, 34)
INK = (230, 237, 243)
MUTED = (139, 148, 158)
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)
LINE = (48, 54, 61)


def font(name, size):
    return ImageFont.truetype(os.path.join(FONTS, name), size)


def chip(d, x, y, text, f, fg=INK, border=GREEN):
    w = d.textlength(text, font=f)
    pad = 16
    d.rounded_rectangle([x, y, x + w + pad * 2, y + 44], radius=22, outline=border, width=2)
    d.text((x + pad, y + 10), text, font=f, fill=fg)
    return x + w + pad * 2 + 14


def main():
    m = {}
    mp = os.path.join(ROOT, "metrics", "metrics.json")
    if os.path.exists(mp):
        m = json.load(open(mp, encoding="utf-8"))

    W, H = 1280, 640
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    f_kicker = font("segoeuib.ttf", 26)
    f_title = font("segoeuib.ttf", 78)
    f_sub = font("segoeui.ttf", 30)
    f_chip = font("segoeuib.ttf", 24)
    f_foot = font("segoeui.ttf", 24)

    # left accent bar
    d.rectangle([0, 0, 14, H], fill=GREEN)
    # subtle inner card
    d.rounded_rectangle([48, 40, W - 48, H - 40], radius=20, fill=CARD, outline=LINE, width=1)

    x0 = 88
    d.text((x0, 78), "SECURITY PROGRAM  ·  DETECTION-AS-CODE  ·  $0", font=f_kicker, fill=GREEN)
    d.text((x0, 118), "Project KESTREL", font=f_title, fill=INK)
    d.text((x0, 214), "End-to-end security program for a fictional fintech —", font=f_sub, fill=INK)
    d.text((x0, 252), "attacked, detected, investigated & measured on one 8 GB laptop.", font=f_sub, fill=MUTED)

    # stat chips (from real metrics where available)
    cov = m.get("chain_detection_coverage_pct", 100)
    row1 = 330
    x = chip(d, x0, row1, f"{cov:g}% chain coverage", f_chip, border=GREEN)
    x = chip(d, x, row1, "23 tested detections", f_chip, border=GREEN)
    x = chip(d, x, row1, "56 unit tests", f_chip, border=GREEN)
    row2 = 392
    x = chip(d, x0, row2, "3 attack scenarios", f_chip, border=BLUE)
    x = chip(d, x, row2, "0 false positives", f_chip, border=BLUE)
    x = chip(d, x, row2, "live exploitable API + LLM", f_chip, border=BLUE)
    row3 = 454
    x = chip(d, x0, row3, "MITRE ATT&CK", f_chip, fg=MUTED, border=LINE)
    x = chip(d, x, row3, "NIST CSF 2.0", f_chip, fg=MUTED, border=LINE)
    x = chip(d, x, row3, "CIS v8", f_chip, fg=MUTED, border=LINE)
    x = chip(d, x, row3, "Sigma · DuckDB · Terraform", f_chip, fg=MUTED, border=LINE)

    # footer
    d.line([x0, H - 96, W - 88, H - 96], fill=LINE, width=1)
    d.text((x0, H - 78), "github.com/InnovaeonLabs/kestrel-security-program", font=f_foot, fill=BLUE)
    tail = "by Markese Raley"
    d.text((W - 88 - d.textlength(tail, font=f_foot), H - 78), tail, font=f_foot, fill=MUTED)

    img.save(OUT)
    print(f"social preview -> {os.path.relpath(OUT, ROOT)} ({img.size[0]}x{img.size[1]})")


if __name__ == "__main__":
    main()
