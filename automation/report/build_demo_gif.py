"""Generate an animated 'terminal replay' demo GIF of the attack -> detection story.

Frame-by-frame with Pillow (no screen recording); content is the project's real
numbers. Output: dashboard/demo.gif  (embed at the top of the README).
Run: python automation/report/build_demo_gif.py
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "dashboard", "demo.gif")
FONTS = "C:/Windows/Fonts"

BG = (13, 17, 23)
GREEN = (63, 185, 80)
BLUE = (88, 166, 255)
AMBER = (210, 153, 34)
RED = (248, 81, 73)
INK = (220, 227, 233)
MUTED = (125, 133, 144)
BAR = (33, 38, 45)

W, H = 900, 600
PAD_X, TOP = 26, 70
LH = 27

# (text, color)  — revealed one line at a time
LINES = [
    ("kestrel@range:~/kestrel-security-program$ make live-attack   # hit the REAL app", GREEN),
    ("  IDOR  GET /payouts/5      -> leaked $1,200 payout (owner=4)", INK),
    ("  SQLi  /merchants/search   -> UNION dumped card tokens", INK),
    ("  SSRF  /fetch-logo         -> reached cloud metadata (IMDS)", INK),
    ("  LLM   /copilot            -> leaked prod signing-key alias", RED),
    ("", INK),
    ("kestrel@range:~$ make detect   # 23 unit-tested Sigma detections", GREEN),
    ("  KP-0016  LLM Prompt Injection .............. CRITICAL", RED),
    ("  KP-0013  SSRF to Cloud Metadata ............ CRITICAL", RED),
    ("  KP-0031  IAM Privilege Escalation .......... CRITICAL", RED),
    ("  KP-0011  SQL Injection Indicators .......... HIGH", AMBER),
    ("  KP-0012  IDOR Payout Enumeration ........... HIGH", AMBER),
    ("  -> 25 alerts | 16 ATT&CK techniques | 0 false positives", BLUE),
    ("", INK),
    ("kestrel@range:~$ make test", GREEN),
    ("  56 passed  [OK]", GREEN),
]
SUMMARY = "100% intrusion coverage  -  0 false positives  -  $0  -  one 8GB laptop"


def _f(name, size):
    try:
        return ImageFont.truetype(os.path.join(FONTS, name), size)
    except OSError:
        return ImageFont.truetype(os.path.join(FONTS, "arial.ttf"), size)


def frame(nlines: int, cursor: bool) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    mono = _f("consola.ttf", 18)
    monob = _f("consolab.ttf", 19)
    # title bar + traffic lights
    d.rectangle([0, 0, W, 44], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([20 + i * 26, 16, 32 + i * 26, 28], fill=c)
    d.text((W // 2 - 150, 14), "Project KESTREL  -  attack -> detection", font=_f("segoeuib.ttf", 18), fill=MUTED)
    # lines
    for i in range(min(nlines, len(LINES))):
        text, color = LINES[i]
        d.text((PAD_X, TOP + i * LH), text, font=mono, fill=color)
    # blinking cursor on the current line
    if cursor and nlines <= len(LINES):
        y = TOP + (nlines - 1) * LH
        tw = d.textlength(LINES[min(nlines - 1, len(LINES) - 1)][0], font=mono)
        d.rectangle([PAD_X + tw + 4, y + 2, PAD_X + tw + 14, y + 20], fill=GREEN)
    # summary bar once all revealed
    if nlines >= len(LINES):
        yb = TOP + (len(LINES) + 1) * LH
        d.rectangle([PAD_X, yb, W - PAD_X, yb + 40], fill=(20, 45, 28))
        d.text((PAD_X + 14, yb + 9), SUMMARY, font=monob, fill=GREEN)
    return img


def main():
    frames, durations = [], []
    for n in range(1, len(LINES) + 1):
        frames.append(frame(n, cursor=True)); durations.append(150)
        frames.append(frame(n, cursor=False)); durations.append(120)
    # hold the final frame, then a short pause before looping
    final = frame(len(LINES), cursor=False)
    frames += [final] * 12
    durations += [180] * 12
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations,
                   loop=0, optimize=True, disposal=2)
    kb = os.path.getsize(OUT) // 1024
    print(f"demo gif -> {os.path.relpath(OUT, ROOT)} ({W}x{H}, {len(frames)} frames, {kb} KB)")


if __name__ == "__main__":
    main()
