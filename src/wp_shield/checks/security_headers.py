"""Check the presence of common security-relevant response headers."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.headers"

_EXPECTED: tuple[tuple[str, str, Severity], ...] = (
    ("content-security-policy", "Content-Security-Policy", Severity.LOW),
    ("strict-transport-security", "Strict-Transport-Security (HSTS)", Severity.MEDIUM),
    ("x-content-type-options", "X-Content-Type-Options", Severity.LOW),
    ("x-frame-options", "X-Frame-Options", Severity.LOW),
    ("referrer-policy", "Referrer-Policy", Severity.INFO),
    ("permissions-policy", "Permissions-Policy", Severity.INFO),
)


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    resp = await http.get(urljoin(base_url, "/"))
    if resp is None:
        return []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    findings: list[Finding] = []
    for key, label, sev in _EXPECTED:
        if key not in headers_lower:
            findings.append(
                Finding(
                    rule_id=f"{RULE_ID}.missing.{key}",
                    title=f"Missing security header: {label}",
                    severity=sev,
                    description=(
                        f"The ``{label}`` response header is not set. "
                        "Configuring it raises the bar against several common "
                        "client-side attack classes."
                    ),
                    location=base_url,
                    remediation=(
                        f"Configure the ``{label}`` header in your web server, "
                        "WordPress security plugin, or CDN."
                    ),
                    references=["https://owasp.org/www-project-secure-headers/"],
                    confidence=Confidence.HIGH,
                    tags=["hardening", "headers"],
                )
            )
    # X-Powered-By / Server header leakage
    if leaked := headers_lower.get("x-powered-by"):
        findings.append(
            Finding(
                rule_id=f"{RULE_ID}.leak.x-powered-by",
                title=f"Server discloses ``X-Powered-By: {leaked}``",
                severity=Severity.INFO,
                description="The X-Powered-By header reveals server-side software details.",
                location=base_url,
                remediation="Remove or suppress the X-Powered-By header.",
                confidence=Confidence.HIGH,
                tags=["information-disclosure"],
            )
        )
    return findings
