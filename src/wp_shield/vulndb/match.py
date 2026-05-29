"""Match detected components against the vulnerability database.

Version comparison is tricky for WordPress: plugin versions don't all follow
PEP-440 / semver. We use ``packaging.version`` with a forgiving fallback that
parses sequences of integers.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from packaging.version import InvalidVersion, Version

from ..models import Component, ComponentType, Severity, Vulnerability
from .store import VulnStore

log = logging.getLogger("wp_shield.vulndb.match")

_NUMERIC_RE = re.compile(r"\d+")


def _safe_version(raw: str) -> Version | tuple[int, ...] | None:
    if raw is None:
        return None
    raw = raw.strip()
    if not raw or raw in {"*", "trunk"}:
        return None
    try:
        return Version(raw)
    except InvalidVersion:
        nums = [int(n) for n in _NUMERIC_RE.findall(raw)[:4]]
        return tuple(nums) if nums else None


def _compare(a: Any, b: Any) -> int:
    """Return -1/0/1 for (a < b, a == b, a > b). Mixed tuple/Version handled."""
    if a is None or b is None:
        return 0  # treat unknown as "matches"
    if isinstance(a, Version) and isinstance(b, Version):
        return (a > b) - (a < b)
    if isinstance(a, tuple) and isinstance(b, tuple):
        return (a > b) - (a < b)
    # Normalize one of them down to a tuple
    if isinstance(a, Version):
        a = tuple(a.release)
    if isinstance(b, Version):
        b = tuple(b.release)
    # Equalize lengths
    L = max(len(a), len(b))
    at = tuple(a) + (0,) * (L - len(a))
    bt = tuple(b) + (0,) * (L - len(b))
    return (at > bt) - (at < bt)


def _in_range(
    detected: str,
    from_version: str | None,
    from_inclusive: bool,
    to_version: str | None,
    to_inclusive: bool,
) -> bool:
    """Whether ``detected`` lies within [from .. to]."""
    d = _safe_version(detected)
    if d is None:
        return False
    if from_version is not None:
        f = _safe_version(from_version)
        if f is not None:
            cmp_f = _compare(d, f)
            if cmp_f < 0 or (cmp_f == 0 and not from_inclusive):
                return False
    if to_version is not None:
        t = _safe_version(to_version)
        if t is not None:
            cmp_t = _compare(d, t)
            if cmp_t > 0 or (cmp_t == 0 and not to_inclusive):
                return False
    return True


def _vuln_record_to_model(rec: dict[str, Any]) -> Vulnerability:
    rng = rec.get("range") or {}
    return Vulnerability(
        uuid=rec["uuid"],
        title=rec["title"],
        severity=Severity(rec.get("severity", "medium")),
        cvss_score=rec.get("cvss_score"),
        cvss_vector=rec.get("cvss_vector"),
        cve_ids=rec.get("cve_ids") or [],
        cwe_ids=rec.get("cwe_ids") or [],
        references=[r.get("url") for r in (rec.get("references") or []) if r.get("url")],
        description=rec.get("description"),
        published_at=rec.get("published_at"),
        source=rec.get("source", "wordfence"),
        affected_slug=rng.get("slug"),
        affected_type=ComponentType(rng["type"]) if rng.get("type") in {"core", "plugin", "theme"} else None,
        from_version=rng.get("from_version"),
        from_inclusive=rng.get("from_inclusive"),
        to_version=rng.get("to_version"),
        to_inclusive=rng.get("to_inclusive"),
    )


def find_vulnerabilities(store: VulnStore, component: Component) -> list[Vulnerability]:
    """Return all vulnerabilities affecting this component."""
    if component.version is None or component.slug is None:
        return []
    type_key = component.type.value
    if component.type == ComponentType.CORE:
        slug = "wordpress"
    else:
        slug = component.slug.lower()
    candidates = store.candidate_vulns_for(slug, type_key)
    matched: list[Vulnerability] = []
    for rec in candidates:
        if _in_range(
            component.version,
            rec.get("from_version"),
            bool(rec.get("from_inclusive")),
            rec.get("to_version"),
            bool(rec.get("to_inclusive", True)),
        ):
            matched.append(_vuln_record_to_model(rec))
    # De-dup by UUID
    seen: set[str] = set()
    unique: list[Vulnerability] = []
    for v in matched:
        if v.uuid in seen:
            continue
        seen.add(v.uuid)
        unique.append(v)
    return unique
