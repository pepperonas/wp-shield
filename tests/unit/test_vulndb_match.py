"""Vulnerability matching: version ranges."""

from __future__ import annotations

from wp_shield.models import Component, ComponentType
from wp_shield.vulndb.match import _in_range, find_vulnerabilities


def test_in_range_closed() -> None:
    # vulnerable from 3.0 (inclusive) to 3.5.0 (inclusive)
    assert _in_range("3.4.0", "3.0", True, "3.5.0", True) is True
    assert _in_range("3.5.0", "3.0", True, "3.5.0", True) is True
    assert _in_range("3.0", "3.0", True, "3.5.0", True) is True
    assert _in_range("3.5.1", "3.0", True, "3.5.0", True) is False
    assert _in_range("2.9.0", "3.0", True, "3.5.0", True) is False


def test_in_range_exclusive_upper() -> None:
    assert _in_range("3.5.0", None, False, "3.5.0", False) is False
    assert _in_range("3.4.9", None, False, "3.5.0", False) is True


def test_in_range_unbounded_lower() -> None:
    # <= 1.2.3
    assert _in_range("1.0", None, False, "1.2.3", True) is True
    assert _in_range("1.2.3", None, False, "1.2.3", True) is True
    assert _in_range("1.2.4", None, False, "1.2.3", True) is False


def test_in_range_handles_unknown_version() -> None:
    # An undetected version (None) should not match any range.
    assert _in_range("", "1.0", True, "2.0", True) is False


def test_find_vulnerabilities_e2e(temp_db) -> None:
    # Seed the DB with one vuln affecting elementor <= 3.5.0
    temp_db.upsert_vulnerabilities([
        {
            "uuid": "abc-123",
            "title": "Elementor pre-3.5.0 XSS",
            "severity": "high",
            "cve_ids": ["CVE-2024-00001"],
            "source": "wordfence",
            "affected": [{
                "slug": "elementor",
                "type": "plugin",
                "from_version": None,
                "from_inclusive": False,
                "to_version": "3.5.0",
                "to_inclusive": True,
            }],
        }
    ])

    vuln_comp = Component(type=ComponentType.PLUGIN, slug="elementor", version="3.4.2")
    safe_comp = Component(type=ComponentType.PLUGIN, slug="elementor", version="3.5.1")
    other_comp = Component(type=ComponentType.PLUGIN, slug="woocommerce", version="1.0")

    assert len(find_vulnerabilities(temp_db, vuln_comp)) == 1
    assert find_vulnerabilities(temp_db, vuln_comp)[0].uuid == "abc-123"
    assert find_vulnerabilities(temp_db, safe_comp) == []
    assert find_vulnerabilities(temp_db, other_comp) == []
