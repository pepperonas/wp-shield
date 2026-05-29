"""Check whether self-service user registration is enabled."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.registration.open"


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    url = urljoin(base_url, "wp-login.php?action=register")
    resp = await http.get(url)
    if resp is None or resp.status_code != 200:
        return []
    body = resp.text.lower()
    if "registration is currently not allowed" in body or "registration is currently disabled" in body:
        return []
    if 'name="user_login"' in body and "register" in body:
        return [
            Finding(
                rule_id=RULE_ID,
                title="User registration is open",
                severity=Severity.LOW,
                description=(
                    "Anyone can create a user account. If the default role is "
                    "``subscriber`` only, the impact is small; combined with a "
                    "vulnerable plugin/theme that exposes admin functionality to "
                    "any logged-in user, this becomes a privilege-escalation path."
                ),
                location=url,
                remediation=(
                    "Disable registration under ``Settings → General`` unless "
                    "your site explicitly needs it (e.g. WooCommerce customers, "
                    "membership site)."
                ),
                confidence=Confidence.HIGH,
                tags=["misconfiguration"],
            )
        ]
    return []
