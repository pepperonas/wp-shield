"""Wordfence feed record transformation."""

from __future__ import annotations

from wp_shield.vulndb.sync import _normalize_severity, _parse_range, _transform_record


def test_normalize_severity_from_score() -> None:
    assert _normalize_severity(0) == "info"
    assert _normalize_severity(2.0) == "low"
    assert _normalize_severity(5.5) == "medium"
    assert _normalize_severity(8.0) == "high"
    assert _normalize_severity(9.8) == "critical"


def test_normalize_severity_from_string() -> None:
    assert _normalize_severity("Critical") == "critical"
    assert _normalize_severity("informational") == "info"
    assert _normalize_severity("MEDIUM") == "medium"


def test_parse_range_object_form() -> None:
    out = _parse_range("", {"from_version": "1.0", "from_inclusive": True,
                            "to_version": "2.0", "to_inclusive": False})
    assert out == {
        "from_version": "1.0",
        "from_inclusive": True,
        "to_version": "2.0",
        "to_inclusive": False,
    }


def test_parse_range_key_form() -> None:
    out = _parse_range("<=3.5.0", {})
    assert out["to_version"] == "3.5.0"
    assert out["to_inclusive"] is True
    assert out["from_version"] is None


def test_transform_record_minimal() -> None:
    rec = {
        "title": "Test vuln",
        "severity": "high",
        "cvss": {"score": 7.5, "vector": "AV:N"},
        "cve": ["CVE-2024-0001"],
        "software": [
            {"type": "plugin", "slug": "elementor",
             "affected_versions": {"<=3.5.0": {"from_version": "*", "to_version": "3.5.0",
                                               "to_inclusive": True}}}
        ],
        "published": "2024-01-01T00:00:00Z",
        "references": ["https://example.com/advisory"],
    }
    out = _transform_record("uuid-1", rec)
    assert out["uuid"] == "uuid-1"
    assert out["severity"] == "high"
    assert out["cvss_score"] == 7.5
    assert out["cve_ids"] == ["CVE-2024-0001"]
    assert out["affected"][0]["slug"] == "elementor"
    assert out["affected"][0]["type"] == "plugin"
    assert out["affected"][0]["to_version"] == "3.5.0"
    assert out["references"][0]["url"] == "https://example.com/advisory"
