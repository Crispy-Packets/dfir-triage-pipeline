"""Palettes and the stylesheet. Colour encodes one thing only: severity.

Severity is ordinal, so it is a single warm hue stepping in lightness —
colour-blind safe by construction, with a ramp per theme validated by the
dataviz skill's `validate_palette.js --ordinal`.
"""
from __future__ import annotations

from pathlib import Path

CSS_PATH = Path(__file__).with_name("styles.css")

PALETTES = {
    # Warm, low-chroma. One accent (clay), a sage "verified" tone, everything
    # else in warm neutrals.
    "dark": {
        "bg": "#0d0e10", "bg2": "#121316", "panel": "#17191d",
        "panel2": "#131519", "line": "#262a30", "line2": "#353b43",
        "text": "#ece6db", "text2": "#c1baae", "muted": "#8a8478",
        "accent": "#d3895a", "accent2": "#e0a880", "hashc": "#cbb28a",
        "card": "#17191d", "track": "#101215", "grid": "#1f242a",
        "sidebar": "#0a0b0d", "shadow": "0 22px 48px -30px #000",
        "seal": "#9caf6a", "seambg": "#141a12",
        "sev-low": "#834226", "sev-med": "#b05e3c", "sev-high": "#d88657",
        "sev-crit": "#f3b88f",
    },
    "light": {
        "bg": "#f1ece1", "bg2": "#eae2d3", "panel": "#fbf8f1",
        "panel2": "#f4efe3", "line": "#e2d9c8", "line2": "#d2c6ae",
        "text": "#2c2418", "text2": "#4c4231", "muted": "#867a64",
        "accent": "#bd6a3d", "accent2": "#a4552d", "hashc": "#8a6f45",
        "card": "#fbf8f1", "track": "#efe9dc", "grid": "#e7decd",
        "sidebar": "#efe8db", "shadow": "0 18px 40px -30px #9a8b6a55",
        "seal": "#7d8f4f", "seambg": "#edefdf",
        "sev-low": "#d69c6f", "sev-med": "#bd7244", "sev-high": "#99492a",
        "sev-crit": "#6c2913",
    },
}


def stylesheet(mode: str = "dark") -> str:
    """The full <style> block for a theme (read-only: the .css file is read,
    never written)."""
    p = PALETTES.get(mode, PALETTES["dark"])
    root = ":root{" + "".join(f"--{k}:{v};" for k, v in p.items()) + "}"
    # The native data grid draws on a canvas that CSS cannot recolour; in the
    # light theme it is re-toned with an invert + hue-rotate so it matches.
    grid = ("[data-testid='stDataFrame'] canvas{ filter:invert(1) "
            "hue-rotate(180deg) sepia(.07) brightness(1.02); }"
            if mode == "light" else "")
    # styles.css opens with its @import (fonts), which must come first.
    return f"<style>{CSS_PATH.read_text(encoding='utf-8')}{root}{grid}</style>"
