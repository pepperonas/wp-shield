"""``xmlrpc.php`` exposure check.

A reachable ``xmlrpc.php`` enables pingback / DDoS-amplification abuse and
brute-force login at scale. Modern WP installs frequently leave it on.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

RULE_ID = "wp.xmlrpc.exposed"


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    url = urljoin(base_url, "xmlrpc.php")
    resp = await http.get(url)
    if resp is None:
        return []
    body = resp.text[:2000] if resp.content else ""
    if resp.status_code == 405 and "xml-rpc server accepts post requests only" in body.lower():
        # Classic WP response to GET
        pass
    elif "xml-rpc server accepts post requests only" not in body.lower():
        if resp.status_code in (404, 403):
            return []  # disabled / blocked

    # Probe with a benign system.listMethods to confirm it's actually accepting RPC calls
    payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
    post = await http.post(url, content=payload, headers={"Content-Type": "text/xml"})
    if post is None or post.status_code >= 400:
        # Reachable but doesn't accept calls — informational only
        return [
            Finding(
                rule_id=RULE_ID,
                title="xmlrpc.php is reachable",
                severity=Severity.LOW,
                description=(
                    "The XML-RPC endpoint is reachable. If RPC methods are enabled, "
                    "it can be abused for pingback DDoS or brute-force login."
                ),
                location=url,
                remediation=(
                    "Disable xmlrpc.php via a security plugin or web-server rule "
                    "unless you specifically need it (e.g. for Jetpack or the WP mobile app)."
                ),
                references=["https://wpscan.com/blog/unauthenticated-xmlrpc-abuse/"],
                confidence=Confidence.MEDIUM,
                tags=["misconfiguration", "xmlrpc"],
            )
        ]

    post_body = post.text
    # A working RPC server replies with <methodResponse>...</methodResponse>.
    # A blocked / dead endpoint either 4xx's or returns the same GET banner.
    if "methodResponse" in post_body and "<fault>" not in post_body:
        return [
            Finding(
                rule_id=RULE_ID + ".rpc_active",
                title="xmlrpc.php accepts XML-RPC method calls",
                severity=Severity.MEDIUM,
                description=(
                    "The XML-RPC endpoint accepted ``system.listMethods``. "
                    "This exposes ``wp.getUsersBlogs`` (login brute-force) and "
                    "``pingback.ping`` (DDoS amplification, SSRF) attack surfaces."
                ),
                evidence=post_body[:400],
                location=url,
                remediation=(
                    "Disable xmlrpc.php entirely, or at minimum disable the "
                    "pingback.ping method and rate-limit POST requests to xmlrpc.php."
                ),
                references=[
                    "https://wpscan.com/blog/unauthenticated-xmlrpc-abuse/",
                    "https://www.acunetix.com/blog/articles/wordpress-pingback-vulnerability/",
                ],
                confidence=Confidence.HIGH,
                tags=["misconfiguration", "xmlrpc", "rce-risk"],
            )
        ]
    return []
