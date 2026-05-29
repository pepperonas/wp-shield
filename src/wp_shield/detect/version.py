"""WordPress core version detection.

Multiple independent sources are queried; the most consistent value wins,
with a confidence score derived from how many sources agreed.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Component, ComponentType, Confidence

# Meta-generator: <meta name="generator" content="WordPress 6.5.2" />
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)',
    re.I,
)
# readme.html: <br /> Version <strong>6.5.2</strong>
_README_VERSION_RE = re.compile(
    r"[Vv]ersion\s*<?[^>]*>?\s*([\d.]+)\s*</?",
)
# RSS / Atom generator tag
_RSS_GENERATOR_RE = re.compile(
    r"<generator>\s*https?://wordpress\.org/\??v?=?([\d.]+)\s*</generator>",
    re.I,
)
# Feed Atom: <generator uri="https://wordpress.org/?v=6.5.2" version="...">
_RSS_GENERATOR_ATTR_RE = re.compile(
    r'<generator[^>]+wordpress\.org/?\??v?=?([\d.]+)',
    re.I,
)
# In emoji-release script: ;src/wp-includes/js/wp-emoji-release.min.js?ver=6.5.2'
_EMOJI_VERSION_RE = re.compile(
    r"wp-emoji-release(?:\.min)?\.js\?ver=([\d.]+)",
    re.I,
)
# Block-library: load-styles.php?...&ver=6.5.2
_BLOCK_LIB_VERSION_RE = re.compile(
    r"wp-block-library[^?\"']*\?ver=([\d.]+)",
    re.I,
)


def _versions_from_html(html: str) -> list[tuple[str, str]]:
    """Pick up version mentions inside a single HTML body.

    Returns ``[(method, version), ...]``.
    """
    out: list[tuple[str, str]] = []
    if m := _META_GENERATOR_RE.search(html):
        out.append(("meta-generator", m.group(1)))
    if m := _EMOJI_VERSION_RE.search(html):
        out.append(("emoji-js", m.group(1)))
    if m := _BLOCK_LIB_VERSION_RE.search(html):
        out.append(("wp-block-library", m.group(1)))
    return out


async def _from_readme(http: HttpClient, base_url: str) -> str | None:
    resp = await http.get(urljoin(base_url, "readme.html"))
    if resp is None or resp.status_code != 200:
        return None
    body = resp.text
    if "wordpress" not in body.lower():
        return None
    if m := _README_VERSION_RE.search(body):
        return m.group(1)
    return None


async def _from_feed(http: HttpClient, base_url: str) -> str | None:
    for path in ("feed/", "?feed=rss2"):
        resp = await http.get(urljoin(base_url, path))
        if resp is None or resp.status_code != 200:
            continue
        body = resp.text[:8000]
        if m := _RSS_GENERATOR_RE.search(body):
            return m.group(1)
        if m := _RSS_GENERATOR_ATTR_RE.search(body):
            return m.group(1)
    return None


async def _from_buttons_css_hash(http: HttpClient, base_url: str) -> str | None:
    """Match the MD5 of `/wp-includes/css/buttons.css` against known versions.

    This is a tiny built-in table for very common versions. It's useful when
    the site strips the generator meta tag. Not exhaustive — extend over time.
    """
    resp = await http.get(urljoin(base_url, "wp-includes/css/buttons.css"))
    if resp is None or resp.status_code != 200:
        return None
    digest = hashlib.md5(resp.content).hexdigest()
    return _BUTTONS_CSS_HASHES.get(digest)


# Limited known-hash table; sparsely populated on purpose — better empty than wrong.
# Source: wpscan-style fingerprinting; could be vastly expanded via release artifacts.
_BUTTONS_CSS_HASHES: dict[str, str] = {
    # placeholder — kept small for v0.1; tooling to regenerate is in scripts/
}


async def detect_version(http: HttpClient, base_url: str, homepage_html: str) -> Component:
    """Detect the WordPress core version."""
    seen: list[tuple[str, str]] = []
    seen.extend(_versions_from_html(homepage_html))

    if v := await _from_readme(http, base_url):
        seen.append(("readme", v))
    if v := await _from_feed(http, base_url):
        seen.append(("rss-generator", v))
    if v := await _from_buttons_css_hash(http, base_url):
        seen.append(("buttons-css-hash", v))

    component = Component(
        type=ComponentType.CORE,
        slug="wordpress",
        name="WordPress",
        detection_methods=[m for m, _ in seen],
    )

    if not seen:
        component.confidence = Confidence.LOW
        return component

    # Majority-vote on version values; tie => first occurrence
    counter = Counter(v for _, v in seen)
    version, agree = counter.most_common(1)[0]
    component.version = version
    if agree >= 3:
        component.confidence = Confidence.HIGH
    elif agree == 2:
        component.confidence = Confidence.MEDIUM
    else:
        component.confidence = Confidence.LOW
    return component
