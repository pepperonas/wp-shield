"""Download the Wordfence vulnerability feed and upsert into the local DB.

As of 2025, Wordfence's v3 feed requires a Bearer API token (free tier still
exists; request one at https://www.wordfence.com/products/wordfence-intelligence/).
v1/v2 endpoints returned HTTP 410 Gone after the v3 migration.

For zero-token users, ``wp-shield`` defaults to WPVulnerability.net — see
``sync_wpvuln.py``.

Feed root (v3): an object whose keys are vulnerability UUIDs and values are
records shaped roughly like::

    {
        "id": "...",
        "title": "...",
        "description": "...",
        "software": [
            {"type": "plugin", "slug": "elementor",
             "affected_versions": {"<=3.5.0": {"from_version": "*", ...}}}
        ],
        "cvss": {"score": "7.5", "vector": "..."},
        "cwe": [...],
        "cve": "CVE-2024-1234",
        "references": [{"url": "..."}],
        "published": "2024-...",
        "updated": "2024-..."
    }
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from typing import Any

import httpx

from .store import VulnStore

log = logging.getLogger("wp_shield.vulndb")

WORDFENCE_FEED_URL = (
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
)


def _normalize_severity(raw: Any) -> str:
    """Map a CVSS score or Wordfence severity to our 5-level scale."""
    if isinstance(raw, str):
        r = raw.strip().lower()
        if r in {"info", "informational"}:
            return "info"
        if r in {"low", "medium", "high", "critical"}:
            return r
    if isinstance(raw, (int, float)):
        s = float(raw)
        if s == 0:
            return "info"
        if s < 4:
            return "low"
        if s < 7:
            return "medium"
        if s < 9:
            return "high"
        return "critical"
    return "medium"


def _parse_range(version_key: str, range_obj: dict[str, Any]) -> dict[str, Any]:
    """Best-effort parse of a Wordfence affected-version range.

    Wordfence uses both a ``version_key`` (e.g. ``<=1.2.3``) and a richer
    object form (``from_version`` / ``to_version`` / ``from_inclusive`` /
    ``to_inclusive``). We prefer the object form when present.
    """
    out: dict[str, Any] = {
        "from_version": None,
        "from_inclusive": False,
        "to_version": None,
        "to_inclusive": True,
    }
    if isinstance(range_obj, dict):
        out["from_version"] = range_obj.get("from_version") or None
        out["to_version"] = range_obj.get("to_version") or None
        if out["from_version"] == "*":
            out["from_version"] = None
        if out["to_version"] == "*":
            out["to_version"] = None
        out["from_inclusive"] = bool(range_obj.get("from_inclusive", False))
        out["to_inclusive"] = bool(range_obj.get("to_inclusive", True))

    if (out["to_version"] is None) and version_key:
        # Fall back to parsing the version-key string.
        k = version_key.strip()
        if k.startswith("<="):
            out["to_version"] = k[2:].strip()
            out["to_inclusive"] = True
        elif k.startswith("<"):
            out["to_version"] = k[1:].strip()
            out["to_inclusive"] = False
        elif k.startswith(">="):
            out["from_version"] = k[2:].strip()
            out["from_inclusive"] = True
        elif k.startswith(">"):
            out["from_version"] = k[1:].strip()
            out["from_inclusive"] = False
        elif k.startswith("="):
            v = k[1:].strip()
            out["from_version"] = v
            out["from_inclusive"] = True
            out["to_version"] = v
            out["to_inclusive"] = True
        elif k and k != "*":
            out["from_version"] = k
            out["from_inclusive"] = True
            out["to_version"] = k
            out["to_inclusive"] = True
    return out


def _iter_affected(software_list: Any) -> Iterator[dict[str, Any]]:
    """Yield (type, slug, range_dict) for each affected version range."""
    if not isinstance(software_list, list):
        return
    for sw in software_list:
        if not isinstance(sw, dict):
            continue
        type_ = sw.get("type", "plugin")
        slug = sw.get("slug") or sw.get("plugin_slug") or sw.get("theme_slug")
        if not slug:
            continue
        slug_norm = str(slug).lower().strip()
        affected = sw.get("affected_versions") or {}
        if isinstance(affected, dict) and affected:
            for vk, vr in affected.items():
                rng = _parse_range(vk, vr if isinstance(vr, dict) else {})
                yield {
                    "slug": slug_norm,
                    "type": type_,
                    **rng,
                }
        else:
            # Sometimes only a free-form ``affected`` string is present
            yield {"slug": slug_norm, "type": type_, "from_version": None,
                   "from_inclusive": False, "to_version": None, "to_inclusive": True}


def _transform_record(uuid: str, rec: dict[str, Any]) -> dict[str, Any]:
    """Map upstream Wordfence record to our DB-friendly shape."""
    title = rec.get("title") or rec.get("name") or uuid
    description = rec.get("description")
    if isinstance(description, dict):
        description = description.get("en") or next(iter(description.values()), "")

    cvss = rec.get("cvss") or {}
    score: Any = None
    vector: Any = None
    if isinstance(cvss, dict):
        score_raw = cvss.get("score") or cvss.get("base_score")
        try:
            score = float(score_raw) if score_raw is not None else None
        except (TypeError, ValueError):
            score = None
        vector = cvss.get("vector")
        if rec.get("severity"):
            severity = _normalize_severity(rec["severity"])
        else:
            severity = _normalize_severity(score)
    else:
        severity = _normalize_severity(rec.get("severity"))

    cve_field = rec.get("cve") or []
    if isinstance(cve_field, str):
        cve_ids = [c.strip() for c in cve_field.split(",") if c.strip()]
    elif isinstance(cve_field, list):
        cve_ids = [str(c).strip() for c in cve_field if c]
    else:
        cve_ids = []

    cwe_field = rec.get("cwe") or []
    if isinstance(cwe_field, list):
        cwe_ids = [str(c).strip() for c in cwe_field if c]
    elif isinstance(cwe_field, (str, int)):
        cwe_ids = [str(cwe_field)]
    else:
        cwe_ids = []

    refs_field = rec.get("references") or []
    references: list[dict[str, str]] = []
    if isinstance(refs_field, list):
        for r in refs_field:
            if isinstance(r, str):
                references.append({"url": r, "type": "advisory"})
            elif isinstance(r, dict) and r.get("url"):
                references.append({"url": r["url"], "type": r.get("type", "advisory")})

    return {
        "uuid": uuid,
        "title": str(title)[:500],
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "description": description,
        "published_at": rec.get("published") or rec.get("created"),
        "updated_at": rec.get("updated") or rec.get("modified"),
        "source": "wordfence",
        "references": references,
        "affected": list(_iter_affected(rec.get("software") or rec.get("software_affected"))),
        "raw_json": json.dumps(rec, separators=(",", ":")),
    }


def _iter_feed_records(payload: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    if isinstance(payload, dict):
        for uuid, rec in payload.items():
            if isinstance(rec, dict):
                yield uuid, rec
    elif isinstance(payload, list):
        for rec in payload:
            if isinstance(rec, dict):
                uuid = rec.get("id") or rec.get("uuid")
                if uuid:
                    yield str(uuid), rec


def sync_wordfence(
    store: VulnStore,
    feed_url: str = WORDFENCE_FEED_URL,
    timeout: float = 60.0,
    chunk_size: int = 500,
    on_progress: Any = None,
    api_token: str | None = None,
) -> int:
    """Download the Wordfence feed and upsert. Returns number of vulns written.

    ``api_token`` is the Wordfence Intelligence Bearer token (required since
    the v3 migration in 2025). Pass ``None`` only if your URL is to a
    self-hosted cache that doesn't enforce auth.
    """
    log.info("Downloading Wordfence feed from %s", feed_url)
    headers = {"Accept": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(feed_url, headers=headers)
        resp.raise_for_status()
        payload = resp.json()

    buffer: list[dict[str, Any]] = []
    total = 0
    for uuid, rec in _iter_feed_records(payload):
        buffer.append(_transform_record(uuid, rec))
        if len(buffer) >= chunk_size:
            total += store.upsert_vulnerabilities(buffer)
            if on_progress:
                on_progress(total)
            buffer.clear()
    if buffer:
        total += store.upsert_vulnerabilities(buffer)
        if on_progress:
            on_progress(total)

    store.set_meta("last_feed_source", "wordfence")
    return total
