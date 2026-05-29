"""Theme enumeration via style.css header parsing."""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Component, ComponentType, Confidence, ScanMode
from ._wordlists import load_theme_wordlist

_THEME_PATH_RE = re.compile(
    r"/wp-content/themes/([a-z0-9][a-z0-9._-]*)/",
    re.I,
)
# style.css header (in a CSS comment block)
_HEADER_FIELD_RE = re.compile(r"^[\s*]*([A-Z][A-Za-z\s]+?):\s*(.+?)\s*$", re.M)


def slugs_in_html(html: str) -> set[str]:
    return {m.group(1).lower() for m in _THEME_PATH_RE.finditer(html)}


def parse_style_header(css: str) -> dict[str, str]:
    """Parse the WordPress style.css header block (first comment)."""
    header_block = css[:4000]  # only the top block matters
    fields: dict[str, str] = {}
    for m in _HEADER_FIELD_RE.finditer(header_block):
        key = m.group(1).strip().lower().replace(" ", "_")
        fields[key] = m.group(2).strip()
    return fields


async def _probe_theme(http: HttpClient, base_url: str, slug: str) -> Component | None:
    url = urljoin(base_url, f"wp-content/themes/{slug}/style.css")
    resp = await http.get(url)
    if resp is None or resp.status_code != 200:
        return None
    body = resp.text
    fields = parse_style_header(body)
    if not fields.get("theme_name") and not fields.get("version"):
        # Not a WordPress style.css header — likely not a theme
        return None
    return Component(
        type=ComponentType.THEME,
        slug=slug,
        name=fields.get("theme_name") or slug,
        version=fields.get("version"),
        confidence=Confidence.HIGH if fields.get("version") else Confidence.MEDIUM,
        detection_methods=["style-css"],
        location=url,
    )


async def enumerate_themes(
    http: HttpClient,
    base_url: str,
    homepage_html: str,
    mode: ScanMode = ScanMode.MIXED,
    wordlist_limit: int = 500,
) -> list[Component]:
    found = slugs_in_html(homepage_html)

    async def probe(slug: str) -> Component | None:
        return await _probe_theme(http, base_url, slug)

    results = await asyncio.gather(*(probe(s) for s in found))
    components: dict[str, Component] = {c.slug: c for c in results if c is not None}

    # Slugs that appeared in HTML but had no detectable style.css → keep low-confidence stub
    for s in found:
        if s not in components:
            components[s] = Component(
                type=ComponentType.THEME,
                slug=s,
                name=s,
                confidence=Confidence.LOW,
                detection_methods=["html-asset"],
            )

    if mode == ScanMode.AGGRESSIVE:
        words = load_theme_wordlist(limit=wordlist_limit)
        targets = [s for s in words if s not in components]
        extra = await asyncio.gather(*(probe(s) for s in targets))
        for c in extra:
            if c is not None:
                components[c.slug] = c

    return list(components.values())
