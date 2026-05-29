"""Reporter renders all output formats without crashing."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from wp_shield.core import reporter
from wp_shield.models import (
    Component,
    ComponentType,
    Confidence,
    Finding,
    ScanMode,
    ScanResult,
    Severity,
    TargetInfo,
    User,
    Vulnerability,
)


def _make_result() -> ScanResult:
    target = TargetInfo(
        raw_input="example.com", url="https://example.com/", host="example.com",
        ip="93.184.216.34", reachable=True, final_url="https://example.com/",
        server_header="nginx", waf=None,
    )
    components = [
        Component(type=ComponentType.CORE, slug="wordpress", version="6.5.2",
                  confidence=Confidence.HIGH, detection_methods=["meta-generator"]),
        Component(type=ComponentType.PLUGIN, slug="elementor", version="3.4.0",
                  confidence=Confidence.HIGH,
                  vulnerabilities=[
                      Vulnerability(uuid="v-1", title="Stored XSS in Elementor",
                                    severity=Severity.HIGH, cve_ids=["CVE-2024-1234"],
                                    references=["https://example.com/advisory"]),
                  ]),
        Component(type=ComponentType.THEME, slug="astra", version="4.0.1",
                  confidence=Confidence.MEDIUM),
    ]
    users = [User(id=1, slug="admin", display_name="Site Admin",
                  detection_methods=["wp-json/users"])]
    findings = [
        Finding(rule_id="wp.xmlrpc.exposed", title="xmlrpc.php is reachable",
                severity=Severity.MEDIUM, location="https://example.com/xmlrpc.php"),
        Finding(rule_id="wp.headers.missing.csp", title="Missing security header: CSP",
                severity=Severity.LOW, location="https://example.com/"),
    ]
    return ScanResult(
        target=target,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        mode=ScanMode.MIXED,
        is_wordpress=True,
        wp_detection_signals=["meta-generator", "wp-content-asset"],
        components=components,
        users=users,
        findings=findings,
        tool={"name": "wp-shield", "version": "0.1.0"},
    )


def test_json_is_valid() -> None:
    result = _make_result()
    raw = reporter.render_json(result)
    parsed = json.loads(raw)
    assert parsed["is_wordpress"] is True
    assert parsed["target"]["host"] == "example.com"
    assert len(parsed["components"]) == 3


def test_html_contains_target_and_severity() -> None:
    result = _make_result()
    html = reporter.render_html(result)
    assert "<html" in html
    assert "example.com" in html
    assert "Elementor" in html
    assert 'class="sev high"' in html
    assert "CVE-2024-1234" in html


def test_sarif_is_valid_2_1_0() -> None:
    result = _make_result()
    raw = reporter.render_sarif(result)
    sarif = json.loads(raw)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "wp-shield"
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert "warning" in levels or "error" in levels


def test_cli_render_does_not_crash() -> None:
    from rich.console import Console
    result = _make_result()
    # Render into a non-tty console buffer
    console = Console(record=True, width=120, force_terminal=False)
    reporter.render_cli(result, console)
    out = console.export_text()
    assert "wp-shield" in out
    assert "Elementor" in out or "elementor" in out
