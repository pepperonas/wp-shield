"""Detect directory listing in well-known WordPress paths."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.directory_listing"

_LISTING_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<title>\s*Index of /", re.I),
    re.compile(r'<h1>\s*Index of /[^<]*</h1>', re.I),
    re.compile(r'<a href="\?C=', re.I),  # Apache mod_autoindex sort links
)


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    paths = (
        "wp-content/uploads/",
        "wp-content/plugins/",
        "wp-content/themes/",
        "wp-includes/",
        "wp-content/",
    )
    findings: list[Finding] = []
    for path in paths:
        url = urljoin(base_url, path)
        resp = await http.get(url)
        if resp is None or resp.status_code != 200:
            continue
        body = (resp.text or "")[:6000]
        if any(p.search(body) for p in _LISTING_PATTERNS):
            findings.append(
                Finding(
                    rule_id=f"{RULE_ID}.{path.rstrip('/').replace('/', '_')}",
                    title=f"Directory listing enabled at /{path}",
                    severity=Severity.LOW if path != "wp-content/uploads/" else Severity.MEDIUM,
                    description=(
                        "The web server returns a browseable directory index. "
                        "This leaks file names of installed plugins, themes, or "
                        "uploads that should be private."
                    ),
                    location=url,
                    remediation=(
                        "Disable mod_autoindex (Apache) or ``autoindex off`` "
                        "(Nginx), or place an ``index.html`` / ``index.php`` "
                        "file in the directory."
                    ),
                    confidence=Confidence.HIGH,
                    tags=["misconfiguration", "information-disclosure"],
                )
            )
    return findings
