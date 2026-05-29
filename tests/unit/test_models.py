"""Sanity tests for core domain models."""

from __future__ import annotations

from datetime import UTC, datetime

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


def test_severity_ordering() -> None:
    assert Severity.INFO.numeric < Severity.LOW.numeric < Severity.MEDIUM.numeric
    assert Severity.HIGH.numeric < Severity.CRITICAL.numeric


def test_severity_sarif_levels() -> None:
    assert Severity.INFO.sarif_level == "note"
    assert Severity.MEDIUM.sarif_level == "warning"
    assert Severity.CRITICAL.sarif_level == "error"


def test_scan_result_aggregations() -> None:
    target = TargetInfo(raw_input="example.com", url="https://example.com/", host="example.com")
    core = Component(type=ComponentType.CORE, slug="wordpress", version="6.5.2",
                     confidence=Confidence.HIGH)
    plugin = Component(type=ComponentType.PLUGIN, slug="elementor", version="3.5.0",
                       vulnerabilities=[
                           Vulnerability(uuid="x", title="t", severity=Severity.HIGH),
                       ])
    theme = Component(type=ComponentType.THEME, slug="astra", version="4.0.0")

    started = datetime.now(UTC)
    finished = datetime.now(UTC)
    result = ScanResult(
        target=target,
        started_at=started,
        is_wordpress=True,
        mode=ScanMode.MIXED,
        components=[core, plugin, theme],
        users=[User(slug="admin", display_name="Admin")],
        findings=[
            Finding(rule_id="r1", title="x", severity=Severity.LOW),
            Finding(rule_id="r2", title="y", severity=Severity.MEDIUM),
        ],
        finished_at=finished,
    )

    assert result.core is core
    assert result.plugins == [plugin]
    assert result.themes == [theme]
    assert result.total_vulnerabilities == 1
    counts = result.severity_counts()
    assert counts["low"] == 1
    assert counts["medium"] == 1
    assert counts["high"] == 1
    assert result.duration_seconds is not None and result.duration_seconds >= 0


def test_scan_result_json_roundtrip() -> None:
    target = TargetInfo(raw_input="example.com", url="https://example.com/", host="example.com")
    res = ScanResult(target=target, is_wordpress=False, mode=ScanMode.PASSIVE)
    s = res.to_json()
    assert "example.com" in s
    assert '"is_wordpress":false' in s.replace(" ", "")
