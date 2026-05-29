"""WPVulnerability.net sync — per-component lookup (no auth, no rate limit token).

WPVulnerability is a free, open-source vulnerability database for WordPress.
Unlike the (since 2025 token-gated) Wordfence feed, WPVulnerability serves
data per slug rather than as a giant bulk feed. We therefore "sync" by
pre-warming the cache with our known plugin/theme wordlists plus a small
set of WP core versions, and also support live lookup during scans.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Iterable
from typing import Any

import httpx

from ..detect._wordlists import load_plugin_wordlist, load_theme_wordlist
from .store import VulnStore

log = logging.getLogger("wp_shield.vulndb.wpvuln")

BASE_URL = "https://www.wpvulnerability.net"

# A small set of WP core minor versions to pre-warm. Most installs run a
# 6.x branch in 2026; older majors are added so older systems still get matched.
DEFAULT_CORE_VERSIONS: tuple[str, ...] = tuple(
    f"{major}.{minor}"
    for major in (6, 5)
    for minor in range(0, 10)
)

OPERATOR_INCLUSIVE = {"le": True, "lt": False, "ge": True, "gt": False, "eq": True}


def _normalize_severity_str(raw: Any) -> str:
    if not raw:
        return "medium"
    s = str(raw).strip().lower()
    if s in {"info", "informational", "i", "n", "none"}:
        return "info"
    if s in {"l", "low"}:
        return "low"
    if s in {"m", "medium"}:
        return "medium"
    if s in {"h", "high"}:
        return "high"
    if s in {"c", "critical"}:
        return "critical"
    return "medium"


def _normalize_severity_from_score(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s == 0:
        return "info"
    if s < 4:
        return "low"
    if s < 7:
        return "medium"
    if s < 9:
        return "high"
    return "critical"


def _decode_html_entities(s: str) -> str:
    from html import unescape
    return unescape(s) if s else s


def _transform_vuln(
    raw: dict[str, Any],
    *,
    slug: str,
    comp_type: str,
) -> dict[str, Any]:
    """Map a single WPVulnerability vuln record to our DB schema."""
    impact = raw.get("impact") or {}
    cvss = impact.get("cvss3") or impact.get("cvss") or {}
    score: float | None = None
    try:
        score = float(cvss.get("score")) if cvss.get("score") is not None else None
    except (TypeError, ValueError):
        score = None
    vector = cvss.get("vector")

    if cvss.get("severity"):
        severity = _normalize_severity_str(cvss["severity"])
    elif score is not None:
        severity = _normalize_severity_from_score(score)
    else:
        severity = _normalize_severity_str(raw.get("severity"))

    sources = raw.get("source") or []
    cve_ids: list[str] = []
    references: list[dict[str, str]] = []
    description: str | None = raw.get("description")
    for s in sources if isinstance(sources, list) else []:
        sid = (s.get("id") or "").strip()
        if sid.upper().startswith("CVE-"):
            cve_ids.append(sid)
        if s.get("link"):
            references.append({"url": s["link"], "type": "advisory"})
        if not description and s.get("description"):
            description = s["description"]

    cwe_field = impact.get("cwe") or []
    cwe_ids: list[str] = []
    if isinstance(cwe_field, list):
        for c in cwe_field:
            if isinstance(c, dict) and c.get("cwe"):
                cwe_ids.append(str(c["cwe"]))
            elif isinstance(c, str):
                cwe_ids.append(c)

    op = raw.get("operator") or {}
    min_v = op.get("min_version")
    max_v = op.get("max_version")
    min_op = (op.get("min_operator") or "").lower() or None
    max_op = (op.get("max_operator") or "").lower() or None
    affected: dict[str, Any] = {
        "slug": slug,
        "type": comp_type,
        "from_version": min_v if min_v not in (None, "", "*") else None,
        "from_inclusive": OPERATOR_INCLUSIVE.get(min_op, True) if min_op else False,
        "to_version": max_v if max_v not in (None, "", "*") else None,
        "to_inclusive": OPERATOR_INCLUSIVE.get(max_op, True) if max_op else True,
    }
    if min_op == "eq" and min_v:
        affected["from_version"] = min_v
        affected["to_version"] = min_v
        affected["from_inclusive"] = True
        affected["to_inclusive"] = True

    return {
        "uuid": raw["uuid"],
        "title": _decode_html_entities(raw.get("name") or raw["uuid"])[:500],
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "description": description,
        "published_at": (sources[0].get("date") if isinstance(sources, list) and sources else None),
        "updated_at": None,
        "source": "wpvulnerability",
        "references": references,
        "affected": [affected],
        "raw_json": json.dumps(raw, separators=(",", ":")),
    }


async def _fetch_component(
    client: httpx.AsyncClient, endpoint: str, slug: str
) -> list[dict[str, Any]] | None:
    """Return the ``data.vulnerability`` list for one slug, or None on error."""
    url = f"{BASE_URL}/{endpoint}/{slug}/"
    try:
        resp = await client.get(url)
    except httpx.HTTPError as exc:
        log.debug("Fetch failed %s: %s", url, exc)
        return None
    if resp.status_code != 200:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("error", 0) != 0:
        return None
    data = payload.get("data") or {}
    vulns = data.get("vulnerability") or []
    if isinstance(vulns, list):
        return vulns
    return None


async def _sync_batch(
    client: httpx.AsyncClient,
    endpoint: str,
    comp_type: str,
    slugs: Iterable[str],
    store: VulnStore,
    on_progress: Callable[[int], None] | None,
    concurrency: int = 8,
) -> int:
    sem = asyncio.Semaphore(concurrency)
    total = 0
    buffer: list[dict[str, Any]] = []

    async def one(slug: str) -> None:
        nonlocal total
        async with sem:
            raw_vulns = await _fetch_component(client, endpoint, slug)
        if not raw_vulns:
            return
        for raw in raw_vulns:
            try:
                buffer.append(_transform_vuln(raw, slug=slug, comp_type=comp_type))
            except KeyError:
                continue

    tasks = [asyncio.create_task(one(s)) for s in slugs]
    for fut in asyncio.as_completed(tasks):
        await fut
        if len(buffer) >= 200:
            n = store.upsert_vulnerabilities(buffer)
            total += n
            buffer.clear()
            if on_progress:
                on_progress(total)
    if buffer:
        total += store.upsert_vulnerabilities(buffer)
        if on_progress:
            on_progress(total)
    return total


async def sync_wpvuln_async(
    store: VulnStore,
    *,
    plugin_limit: int = 500,
    theme_limit: int = 200,
    core_versions: Iterable[str] = DEFAULT_CORE_VERSIONS,
    extra_plugins: Iterable[str] = (),
    extra_themes: Iterable[str] = (),
    concurrency: int = 8,
    on_progress: Callable[[int], None] | None = None,
) -> int:
    timeout = httpx.Timeout(20.0, connect=10.0)
    headers = {"User-Agent": "wp-shield/0.1 (vulndb-sync)"}
    async with httpx.AsyncClient(timeout=timeout, headers=headers,
                                 follow_redirects=True, http2=True) as client:
        plugins = list(dict.fromkeys(list(extra_plugins) + load_plugin_wordlist(limit=plugin_limit)))
        themes = list(dict.fromkeys(list(extra_themes) + load_theme_wordlist(limit=theme_limit)))
        total = 0
        total += await _sync_batch(client, "core", "core", core_versions, store, on_progress, concurrency)
        total += await _sync_batch(client, "plugin", "plugin", plugins, store, on_progress, concurrency)
        total += await _sync_batch(client, "theme", "theme", themes, store, on_progress, concurrency)
    store.set_meta("last_feed_source", "wpvulnerability")
    return total


def sync_wpvuln(
    store: VulnStore,
    *,
    plugin_limit: int = 500,
    theme_limit: int = 200,
    core_versions: Iterable[str] = DEFAULT_CORE_VERSIONS,
    on_progress: Callable[[int], None] | None = None,
    concurrency: int = 8,
) -> int:
    return asyncio.run(sync_wpvuln_async(
        store,
        plugin_limit=plugin_limit,
        theme_limit=theme_limit,
        core_versions=core_versions,
        concurrency=concurrency,
        on_progress=on_progress,
    ))


async def lookup_component(
    client: httpx.AsyncClient,
    *,
    comp_type: str,
    slug: str,
) -> list[dict[str, Any]]:
    """Live lookup for a single component. Used when DB has no record."""
    endpoint = {"core": "core", "plugin": "plugin", "theme": "theme"}.get(comp_type)
    if endpoint is None:
        return []
    raw_vulns = await _fetch_component(client, endpoint, slug)
    if not raw_vulns:
        return []
    return [_transform_vuln(rv, slug=slug, comp_type=comp_type) for rv in raw_vulns]
