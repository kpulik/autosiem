"""The rendered palette: OKLCH tokens, hex fallbacks, and readable contrast.

Colour is checked here rather than eyeballed because the previous palette had a
severe defect nobody saw: button labels were white on a light cyan gradient at
1.66:1, so every button in the app ("Search", "Approve", "Load demo telemetry")
had effectively unreadable text. A screenshot does not catch that; arithmetic
does.
"""

from __future__ import annotations

import math
import re

import pytest

from autosiem.web.api import _page

CSS = _page("t", "<p>body</p>")

#: WCAG 2.1 AA for normal-size text.
AA = 4.5


def _tokens() -> dict[str, tuple[float, float, float]]:
    """Every --token declared with an oklch() value, as (L, C, H)."""
    found = re.findall(r"--([a-z-]+):oklch\(([\d.]+) ([\d.]+) ([\d.]+)\)", CSS)
    return {name: (float(l), float(c), float(h)) for name, l, c, h in found}


def _srgb(value: float) -> float:
    value = max(0.0, min(1.0, value))
    return 12.92 * value if value <= 0.0031308 else 1.055 * (value ** (1 / 2.4)) - 0.055


def _oklch_to_rgb(lch: tuple[float, float, float]) -> tuple[float, float, float]:
    lightness, chroma, hue = lch
    a = chroma * math.cos(math.radians(hue))
    b = chroma * math.sin(math.radians(hue))
    l_ = lightness + 0.3963377774 * a + 0.2158037573 * b
    m_ = lightness - 0.1055613458 * a - 0.0638541728 * b
    s_ = lightness - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    return (
        _srgb(+4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
        _srgb(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
        _srgb(-0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s),
    )


def _luminance(lch: tuple[float, float, float]) -> float:
    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(v) for v in _oklch_to_rgb(lch))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _contrast(fg: str, bg: str) -> float:
    tokens = _tokens()
    high, low = sorted((_luminance(tokens[fg]), _luminance(tokens[bg])), reverse=True)
    return (high + 0.05) / (low + 0.05)


# -- the tokens themselves -------------------------------------------------

def test_the_palette_is_declared_in_oklch() -> None:
    tokens = _tokens()
    for required in ("bg", "panel", "card", "raised", "text", "muted", "accent", "danger", "ok"):
        assert required in tokens, f"--{required} is not an oklch() token"


def test_every_oklch_token_has_a_hex_fallback_first() -> None:
    """An older pinned SOC browser must still get the intended colour."""
    for name in _tokens():
        pattern = rf"--{name}:#[0-9a-f]{{6}};\s*--{name}:oklch\("
        assert re.search(pattern, CSS), f"--{name} has no hex fallback before its oklch()"


def test_no_stray_colour_literals_outside_the_fallbacks() -> None:
    """A literal in a rule is a colour that escapes the token system."""
    body = CSS[CSS.index("body {"):]
    stray = set(re.findall(r"#[0-9a-fA-F]{6}\b", body)) | set(re.findall(r"rgba?\([^)]*\)", body))
    assert not stray, f"literal colours outside :root: {sorted(stray)}"


def test_the_surface_ramp_is_evenly_spaced() -> None:
    """The point of OKLCH here: sRGB lightness is not perceptual, so the old
    hex ramp stepped unevenly even though the numbers looked regular."""
    tokens = _tokens()
    ramp = [tokens[name][0] for name in ("bg", "panel", "card", "raised")]
    steps = [round(b - a, 4) for a, b in zip(ramp, ramp[1:])]
    assert len(set(steps)) == 1, f"surface lightness steps are uneven: {steps}"


def test_the_surfaces_share_one_hue() -> None:
    tokens = _tokens()
    hues = {tokens[name][2] for name in ("bg", "panel", "card", "raised")}
    assert len(hues) == 1, f"surfaces drift across hues: {hues}"


def test_danger_carries_the_most_chroma_of_the_status_colours() -> None:
    """It is the alarm; it should win attention against ok and warn."""
    tokens = _tokens()
    assert tokens["danger"][1] > tokens["ok"][1]
    assert tokens["danger"][1] > tokens["warn"][1]


# -- contrast --------------------------------------------------------------

@pytest.mark.parametrize(("foreground", "background"), [
    ("text", "bg"), ("text", "panel"), ("text", "card"),
    ("dim", "card"), ("dim", "raised"),
    ("muted", "bg"), ("muted", "panel"),
    ("accent", "panel"), ("danger", "panel"), ("ok", "panel"), ("warn", "panel"),
])
def test_foreground_pairs_meet_wcag_aa(foreground: str, background: str) -> None:
    ratio = _contrast(foreground, background)
    assert ratio >= AA, f"{foreground} on {background} is {ratio:.2f}:1, below AA"


@pytest.mark.parametrize("gradient_stop", ["accent", "accent-deep"])
def test_button_labels_are_readable_at_both_gradient_stops(gradient_stop: str) -> None:
    """The regression this file exists for.

    Buttons are a cyan-to-indigo gradient. The label was white, which measured
    1.66:1 against the cyan end. It is now --bg, which passes at both ends.
    """
    ratio = _contrast("bg", gradient_stop)
    assert ratio >= AA, f"button label on {gradient_stop} is {ratio:.2f}:1, below AA"
