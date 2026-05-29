"""VulnStore CRUD + scan_history."""

from __future__ import annotations

from datetime import UTC, datetime


def test_upsert_and_query(temp_db) -> None:
    records = [
        {
            "uuid": "v-1",
            "title": "First",
            "severity": "high",
            "cve_ids": ["CVE-2024-1"],
            "source": "wordfence",
            "affected": [{
                "slug": "elementor", "type": "plugin",
                "from_version": None, "from_inclusive": False,
                "to_version": "3.5.0", "to_inclusive": True,
            }],
        },
        {
            "uuid": "v-2",
            "title": "Second",
            "severity": "medium",
            "source": "wordfence",
            "affected": [{
                "slug": "wordpress", "type": "core",
                "from_version": "6.0", "from_inclusive": True,
                "to_version": "6.5.1", "to_inclusive": True,
            }],
        },
    ]
    temp_db.upsert_vulnerabilities(records)

    stats = temp_db.stats()
    assert stats["total_vulnerabilities"] == 2
    assert stats["by_component_type"].get("plugin") == 1
    assert stats["by_component_type"].get("core") == 1

    # idempotent: re-upsert doesn't double rows
    temp_db.upsert_vulnerabilities(records)
    assert temp_db.stats()["total_vulnerabilities"] == 2

    # candidate query
    cands = temp_db.candidate_vulns_for("elementor", "plugin")
    assert len(cands) == 1
    assert cands[0]["uuid"] == "v-1"


def test_scan_history(temp_db) -> None:
    now = datetime.now(UTC)
    sid = temp_db.record_scan(
        target_url="https://example.com/",
        started_at=now,
        finished_at=now,
        mode="mixed",
        is_wordpress=True,
        finding_count=3,
        vuln_count=2,
        report_json="{}",
    )
    assert sid > 0
    scans = temp_db.list_scans()
    assert scans[0]["target_url"] == "https://example.com/"
    assert scans[0]["finding_count"] == 3
