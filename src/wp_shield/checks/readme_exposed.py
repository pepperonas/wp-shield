"""WP ``readme.html`` discloses the WordPress version to attackers."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.readme.exposed"


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, label in (
        ("readme.html", "WordPress readme.html"),
        ("license.txt", "WordPress license.txt"),
        ("wp-includes/version.php", "WordPress version.php"),
    ):
        url = urljoin(base_url, path)
        resp = await http.get(url)
        if resp is None or resp.status_code != 200:
            continue
        body = (resp.text or "")[:1000]
        if "wordpress" in body.lower() or "license.txt" in path:
            findings.append(
                Finding(
                    rule_id=f"{RULE_ID}.{path.replace('/', '_').replace('.', '_')}",
                    title=f"{label} is reachable",
                    severity=Severity.INFO,
                    description=(
                        "Exposing this file makes WordPress version fingerprinting trivial."
                    ),
                    location=url,
                    remediation=(
                        "Block access via a web-server rule or restrict "
                        "to authenticated users."
                    ),
                    confidence=Confidence.HIGH,
                    tags=["information-disclosure"],
                )
            )
    return findings
