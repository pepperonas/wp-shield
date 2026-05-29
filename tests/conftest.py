"""Pytest configuration and shared fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from wp_shield.settings import HttpSettings
from wp_shield.vulndb.store import VulnStore


@pytest.fixture
def http_settings() -> HttpSettings:
    return HttpSettings(
        timeout=5,
        max_concurrency=4,
        respect_robots_txt=False,
        rate_limit_per_second=1000,  # disable practical rate-limiting
        verify_ssl=False,
    )


@pytest.fixture
def temp_db(tmp_path: Path) -> VulnStore:
    return VulnStore(path=tmp_path / "wp_shield_test.sqlite")


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"
