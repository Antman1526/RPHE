#!/usr/bin/env python3
"""Generate the RPHE app icon: a white padlock on the brand blue.

Produces packaging/RPHE.icns (macOS), packaging/RPHE.ico (Windows), and
packaging/icon_preview.png. Reproducible — re-run to tweak the design.

Needs Pillow:  pip install pillow
macOS .icns needs the system `iconutil` (preinstalled).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging"
SS = 4                       # supersample for smooth edges
BASE = 1024
SIZE = BASE * SS

BLUE_TOP = (59, 130, 246)    # #3b82f6
BLUE_BOT = (29, 78, 216)     # #1d4ed8
KEY_BLUE = (37, 99, 235)     # #2563eb (keyhole cut-out)
WHITE = (255, 255, 255, 255)


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def render(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    # Brand-blue rounded-square background with a soft vertical gradient.
    grad = Image.new("RGB", (size, size))
    gd = ImageDraw.Draw(grad)
    for y in range(size):
        gd.line([(0, y), (size, y)], fill=_lerp(BLUE_TOP, BLUE_BOT, y / size))
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, size - 1, size - 1], radius=int(size * 0.225), fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    cx = size / 2

    # --- padlock body ---
    body_w, body_h = size * 0.50, size * 0.34
    body_top = size * 0.45
    d.rounded_rectangle(
        [cx - body_w / 2, body_top, cx + body_w / 2, body_top + body_h],
        radius=size * 0.065, fill=WHITE)

    # --- shackle (top semicircle + two legs into the body) ---
    shk_r = size * 0.145
    shk_w = size * 0.078
    shk_cy = body_top + size * 0.01
    d.arc([cx - shk_r, shk_cy - shk_r, cx + shk_r, shk_cy + shk_r],
          start=180, end=360, fill=WHITE, width=int(shk_w))
    for lx in (cx - shk_r, cx + shk_r):
        d.line([(lx, shk_cy), (lx, body_top + size * 0.02)], fill=WHITE, width=int(shk_w))
        d.ellipse([lx - shk_w / 2, shk_cy - shk_w / 2,
                   lx + shk_w / 2, shk_cy + shk_w / 2], fill=WHITE)

    # --- keyhole (cut into the body, brand blue) ---
    kh_cy = body_top + body_h * 0.40
    kh_r = size * 0.055
    d.ellipse([cx - kh_r, kh_cy - kh_r, cx + kh_r, kh_cy + kh_r], fill=KEY_BLUE)
    top_w, bot_w = kh_r * 0.85, kh_r * 1.6
    stem_bot = body_top + body_h * 0.78
    d.polygon([(cx - top_w, kh_cy), (cx + top_w, kh_cy),
               (cx + bot_w, stem_bot), (cx - bot_w, stem_bot)], fill=KEY_BLUE)

    return img


def main() -> None:
    master = render(SIZE).resize((BASE, BASE), Image.LANCZOS)
    master.save(PKG / "icon_preview.png")

    iconset = PKG / "RPHE.iconset"
    iconset.mkdir(exist_ok=True)
    for px, name in [(16, "16x16"), (32, "16x16@2x"), (32, "32x32"),
                     (64, "32x32@2x"), (128, "128x128"), (256, "128x128@2x"),
                     (256, "256x256"), (512, "256x256@2x"), (512, "512x512"),
                     (1024, "512x512@2x")]:
        master.resize((px, px), Image.LANCZOS).save(iconset / f"icon_{name}.png")

    if sys.platform == "darwin":
        subprocess.run(["iconutil", "-c", "icns", str(iconset),
                        "-o", str(PKG / "RPHE.icns")], check=True)

    master.save(PKG / "RPHE.ico",
                sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("wrote RPHE.icns, RPHE.ico, icon_preview.png")


if __name__ == "__main__":
    main()
