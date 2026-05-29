"""``wp-content/debug.log`` exposed to the public — common source of secrets."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.debug_log.exposed"


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    url = urljoin(base_url, "wp-content/debug.log")
    resp = await http.get(url)
    if resp is None or resp.status_code != 200:
        return []
    body = resp.text[:1000] if resp.content else ""
    if not body or "<html" in body.lower()[:200]:
        return []
    return [
        Finding(
            rule_id=RULE_ID,
            title="debug.log is publicly accessible",
            severity=Severity.HIGH,
            description=(
                "WordPress's debug log can contain PHP errors with database "
                "queries, paths, plugin internals, and even secrets. It must "
                "never be web-accessible."
            ),
            evidence=body[:300],
            location=url,
            remediation=(
                "Disable WP_DEBUG_LOG in wp-config.php on production OR block "
                "``debug.log`` via web-server rules. Move logs out of the web root."
            ),
            references=[
                "https://wordpress.org/documentation/article/debugging-in-wordpress/",
            ],
            confidence=Confidence.HIGH,
            tags=["misconfiguration", "information-disclosure", "secrets"],
        )
    ]
