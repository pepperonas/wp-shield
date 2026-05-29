"""Plugin enumeration.

Three modes:

* ``passive``   — parse the homepage HTML only, extract plugin slugs from
                  ``/wp-content/plugins/<slug>/...`` asset URLs.
* ``mixed``     — passive + fetch ``readme.txt`` / ``readme.html`` for each
                  detected slug to extract the version.
* ``aggressive``— mixed + probe an additional wordlist of popular plugins.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Component, ComponentType, Confidence, ScanMode
from ._wordlists import load_plugin_wordlist

_PLUGIN_PATH_RE = re.compile(
    r"/wp-content/plugins/([a-z0-9][a-z0-9._-]*)/",
    re.I,
)
_STABLE_TAG_RE = re.compile(r"^\s*Stable tag:\s*([^\s]+)\s*$", re.I | re.M)
_README_VERSION_RE = re.compile(r"=\s*([\d.][\d.\w-]*)\s*=\s*(\d{4}-\d{2}-\d{2}|.*?)$", re.M)


def slugs_in_html(html: str) -> set[str]:
    """Extract unique plugin slugs from HTML."""
    return {m.group(1).lower() for m in _PLUGIN_PATH_RE.finditer(html)}


async def _probe_plugin(http: HttpClient, base_url: str, slug: str) -> Component | None:
    """Confirm a plugin slug exists and extract its version from readme.txt."""
    readme_url = urljoin(base_url, f"wp-content/plugins/{slug}/readme.txt")
    resp = await http.get(readme_url)
    if resp is None or resp.status_code != 200:
        # Try readme.html as a fallback
        alt = urljoin(base_url, f"wp-content/plugins/{slug}/readme.html")
        resp = await http.get(alt)
        if resp is None or resp.status_code != 200:
            return None
        readme_url = alt
    body = resp.text
    version: str | None = None
    if m := _STABLE_TAG_RE.search(body):
        v = m.group(1).strip()
        if v.lower() != "trunk":
            version = v
    if version is None:
        if m := _README_VERSION_RE.search(body):
            version = m.group(1).strip()
    return Component(
        type=ComponentType.PLUGIN,
        slug=slug,
        name=slug,
        version=version,
        confidence=Confidence.HIGH if version else Confidence.MEDIUM,
        detection_methods=["readme-probe"],
        location=readme_url,
    )


async def enumerate_plugins(
    http: HttpClient,
    base_url: str,
    homepage_html: str,
    mode: ScanMode = ScanMode.MIXED,
    wordlist_limit: int = 1500,
) -> list[Component]:
    """Enumerate installed plugins. See module docstring for mode semantics."""
    found_slugs = slugs_in_html(homepage_html)

    components: dict[str, Component] = {}
    for slug in found_slugs:
        components[slug] = Component(
            type=ComponentType.PLUGIN,
            slug=slug,
            name=slug,
            confidence=Confidence.MEDIUM,
            detection_methods=["html-asset"],
        )

    if mode == ScanMode.PASSIVE:
        return list(components.values())

    # mixed + aggressive: probe readme.txt for each known slug to learn version
    async def probe(slug: str) -> None:
        comp = await _probe_plugin(http, base_url, slug)
        if comp is None:
            return
        existing = components.get(slug)
        if existing is None:
            components[slug] = comp
        else:
            existing.version = existing.version or comp.version
            existing.confidence = Confidence.HIGH if comp.version else existing.confidence
            existing.detection_methods.extend(comp.detection_methods)
            existing.location = existing.location or comp.location

    await asyncio.gather(*(probe(s) for s in list(found_slugs)))

    if mode == ScanMode.AGGRESSIVE:
        wordlist = load_plugin_wordlist(limit=wordlist_limit)
        # Skip slugs we already found
        targets = [s for s in wordlist if s not in components]

        async def probe_unknown(slug: str) -> None:
            comp = await _probe_plugin(http, base_url, slug)
            if comp is not None:
                components[slug] = comp

        await asyncio.gather(*(probe_unknown(s) for s in targets))

    return list(components.values())
