"""Random presets and the request headers that go with a preset.

A TLS hello that says "Chrome 153" attached to user-agent Go-http-client/2.0
is flagged at the header layer before the handshake is even weighed. So every
preset resolves to the navigation headers the real browser sends, in the real
order, and the caller only overrides what differs.

``resolve_preset`` also accepts a family name ("chrome", "firefox", "safari",
"opera", "edge", "tor", ...) or "random", the way primp's impersonate="random"
works, and picks a member at random per Session. Headers follow the pick, so
the user-agent, sec-ch-ua and header order always tell the same story as the
handshake.

sec-ch-ua is computed with Chromium's own algorithm
(components/embedder_support/user_agent_utils.cc): the "Not A Brand" spelling,
its version and the order of the three brands are all seeded by the major
version. Checked against real Chrome 120, 131, 133 and 153 and Edge 153.
"""

import random
import re
from typing import Optional

from .settings import CLIENT_IDENTIFIERS

# Families that are real browsers. App profiles (nike, zalando, okhttp...) are
# left out of "random" because their headers are the app's, not a browser's.
BROWSER_FAMILIES = (
    "chrome", "chromium", "edge", "brave", "opera",
    "firefox", "tor", "safari", "safari_ios", "safari_ipad",
)

_IDENT = re.compile(r"^([a-z]+(?:_ios|_ipad)?)_(\d+(?:_\d+)*)(?:_PSK(?:_PQ)?)?$")


def _parse(identifier: str):
    """'safari_ios_18_5' -> ('safari_ios', [18, 5]); None for app profiles."""
    m = _IDENT.match(identifier)
    if not m or m.group(1) not in BROWSER_FAMILIES:
        return None
    return m.group(1), [int(x) for x in m.group(2).split("_")]


def members(family: str) -> list:
    """The identifiers of one family, plain variants only (no _PSK), oldest
    first."""
    found = [(p[1], i) for i in CLIENT_IDENTIFIERS
             if not i.endswith(("_PSK", "_PQ")) and (p := _parse(i)) and p[0] == family]
    return [i for _, i in sorted(found)]


# A family pick stays within its newest releases: a Chrome from 2022 in a
# 2026 traffic mix is a tell of its own, not variety.
RECENT = 5


def resolve_preset(preset: str, rng=random) -> str:
    """Turn 'random' or a family name into a concrete identifier."""
    if preset in CLIENT_IDENTIFIERS:
        return preset
    if preset == "random":
        preset = rng.choice(("chrome", "edge", "opera", "firefox", "safari"))
    if preset in BROWSER_FAMILIES:
        return rng.choice(members(preset)[-RECENT:])
    raise KeyError(preset)


# -- sec-ch-ua, Chromium's algorithm ----------------------------------------
_GREASY_CHARS = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
_GREASED_VERSIONS = ["8", "99", "24"]
_ORDERS3 = [(0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0)]


def sec_ch_ua(chromium: int, brand: Optional[str] = None, brand_version: Optional[int] = None) -> str:
    seed = chromium
    grease = (
        "Not" + _GREASY_CHARS[seed % 11] + "A" + _GREASY_CHARS[(seed + 1) % 11] + "Brand",
        _GREASED_VERSIONS[seed % 3],
    )
    entries = [grease, ("Chromium", str(chromium))]
    if brand:
        entries.append((brand, str(brand_version or chromium)))
    order = (seed % 2, (seed + 1) % 2) if len(entries) == 2 else _ORDERS3[seed % 6]
    shuffled = [None] * len(entries)
    for i, slot in enumerate(order):
        shuffled[slot] = entries[i]
    return ", ".join(f'"{b}";v="{v}"' for b, v in shuffled)


def opera_chromium(opera: int) -> int:
    """Opera's Chromium base: +14, then +15 past Chromium 129, +16 past 136
    (both skipped by Opera). Mirrors the table in profiles/opera_profiles.go."""
    return opera + (14 if opera <= 114 else 15 if opera <= 120 else 16)


# -- headers per family ------------------------------------------------------
_CHROME_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                  "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
_FIREFOX_ACCEPT_OLD = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
_FIREFOX_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
                   "image/webp,image/png,image/svg+xml,*/*;q=0.8")
_SAFARI_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_WIN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36"


def _chromium(chromium: int, ua: str, ch: str) -> dict:
    h = {
        "sec-ch-ua": ch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "upgrade-insecure-requests": "1",
        "user-agent": ua,
        "accept": _CHROME_ACCEPT,
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "accept-encoding": "gzip, deflate, br, zstd" if chromium >= 123 else "gzip, deflate, br",
        "accept-language": "en-US,en;q=0.9",
    }
    if chromium >= 124:
        h["priority"] = "u=0, i"
    return h


def _gecko(rv: int, ua: str, tor: bool) -> dict:
    h = {
        "user-agent": ua,
        "accept": _FIREFOX_ACCEPT if rv >= 128 else _FIREFOX_ACCEPT_OLD,
        "accept-language": "en-US,en;q=0.5",
        "accept-encoding": "gzip, deflate, br, zstd" if rv >= 126 else "gzip, deflate, br",
    }
    if tor:
        h["sec-gpc"] = "1"
    h.update({
        "upgrade-insecure-requests": "1",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
    })
    if rv >= 128:
        h["priority"] = "u=0, i"
    h["te"] = "trailers"
    return h


def _webkit(major: int, ua: str) -> dict:
    h = {
        "accept": _SAFARI_ACCEPT,
        "sec-fetch-site": "none",
        "accept-encoding": "gzip, deflate, br",
        "sec-fetch-mode": "navigate",
        "user-agent": ua,
        "accept-language": "en-US,en;q=0.9",
        "sec-fetch-dest": "document",
    }
    if major >= 17:
        h["priority"] = "u=0, i"
    return h


_TOR_ESR = {13: 115, 14: 128, 15: 140}
_WEBKIT_UA = "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s"


def browser_headers(identifier: str) -> Optional[dict]:
    """The navigation headers the browser behind ``identifier`` sends, in its
    order (dict order is the header order). None for app profiles."""
    parsed = _parse(identifier)
    if not parsed:
        return None
    family, v = parsed
    major = v[0]

    if family == "chrome":
        return _chromium(major, _WIN_UA % major, sec_ch_ua(major, "Google Chrome"))
    if family == "chromium":
        return _chromium(major, _WIN_UA % major, sec_ch_ua(major))
    if family == "edge":
        return _chromium(major, _WIN_UA % major + " Edg/%d.0.0.0" % major, sec_ch_ua(major, "Microsoft Edge"))
    if family == "brave":
        return _chromium(major, _WIN_UA % major, sec_ch_ua(major, "Brave"))
    if family == "opera":
        base = opera_chromium(major)
        return _chromium(base, _WIN_UA % base + " OPR/%d.0.0.0" % major, sec_ch_ua(base, "Opera", major))
    if family == "firefox":
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (major, major)
        return _gecko(major, ua, tor=False)
    if family == "tor":
        rv = _TOR_ESR[major]
        # resistFingerprinting spoofs the OS; 15.x started adding Win64; x64.
        os_ = "Windows NT 10.0; Win64; x64" if major >= 15 else "Windows NT 10.0"
        return _gecko(rv, "Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (os_, rv, rv), tor=True)

    ver = ".".join(map(str, v))
    if family == "safari":
        return _webkit(major, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " + _WEBKIT_UA % ver + " Safari/605.1.15")
    dev = "iPhone; CPU iPhone OS" if family == "safari_ios" else "iPad; CPU OS"
    return _webkit(major, "Mozilla/5.0 (%s %s like Mac OS X) " % (dev, "_".join(map(str, v))) + _WEBKIT_UA % ver + " Mobile/15E148 Safari/604.1")
