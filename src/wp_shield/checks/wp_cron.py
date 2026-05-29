"""Detect publicly-triggerable wp-cron.php.

Default WP installs allow ``GET /wp-cron.php`` to run scheduled tasks. On busy
sites this enables a low-effort DoS by flooding the endpoint.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.wpcron.exposed"


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    url = urljoin(base_url, "wp-cron.php")
    resp = await http.get(url)
    if resp is None:
        return []
    if resp.status_code in (200, 408, 504):
        return [
            Finding(
                rule_id=RULE_ID,
                title="wp-cron.php is publicly reachable",
                severity=Severity.LOW,
                description=(
                    "Anyone can trigger scheduled tasks by requesting wp-cron.php. "
                    "On high-traffic or resource-constrained sites this is a "
                    "low-effort DoS vector."
                ),
                location=url,
                remediation=(
                    "Set ``define('DISABLE_WP_CRON', true);`` in wp-config.php "
                    "and run wp-cron via a real OS cron (``wget`` / ``wp cron event run``)."
                ),
                references=[
                    "https://developer.wordpress.org/plugins/cron/hooking-wp-cron-into-the-system-task-scheduler/",
                ],
                confidence=Confidence.HIGH,
                tags=["misconfiguration", "dos"],
            )
        ]
    return []
