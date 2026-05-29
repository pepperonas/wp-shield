"""User-facing settings — loaded from YAML, env, or CLI overrides."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from platformdirs import user_cache_dir, user_config_dir, user_data_dir
from pydantic import BaseModel, Field

from .models import ScanMode

APP_NAME = "wp-shield"
APP_AUTHOR = "wp-shield"


def config_dir() -> Path:
    """XDG-compliant config directory."""
    return Path(user_config_dir(APP_NAME, APP_AUTHOR))


def data_dir() -> Path:
    """XDG-compliant data directory (DB lives here)."""
    return Path(user_data_dir(APP_NAME, APP_AUTHOR))


def cache_dir() -> Path:
    return Path(user_cache_dir(APP_NAME, APP_AUTHOR))


def ensure_dirs() -> None:
    for d in (config_dir(), data_dir(), cache_dir()):
        d.mkdir(parents=True, exist_ok=True)


def db_path() -> Path:
    return data_dir() / "wp_shield.sqlite"


def owned_domains_path() -> Path:
    return config_dir() / "owned-domains.txt"


def config_path() -> Path:
    return config_dir() / "config.yaml"


DEFAULT_USER_AGENT = (
    "wp-shield/0.1 (+https://github.com/pepperonas/wp-shield)"
)


class HttpSettings(BaseModel):
    timeout: float = 15.0
    max_concurrency: int = 10
    user_agent: str = DEFAULT_USER_AGENT
    rotate_user_agent: bool = False
    respect_robots_txt: bool = True
    rate_limit_per_second: float = 5.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    proxy: str | None = None
    max_retries: int = 2


class ScanSettings(BaseModel):
    default_mode: ScanMode = ScanMode.MIXED
    enumerate_users: bool = True
    enumerate_plugins: bool = True
    enumerate_themes: bool = True
    check_misconfigurations: bool = True
    check_config_backups: bool = True
    match_vulnerabilities: bool = True
    max_users_to_probe: int = 50
    plugin_wordlist_limit: int = 1500


class VulnDbSettings(BaseModel):
    source: str = "wordfence"  # wordfence | wpvulnerability
    auto_update_max_age_hours: int = 24


class OutputSettings(BaseModel):
    default_format: str = "cli"
    color: str = "auto"


class Settings(BaseModel):
    http: HttpSettings = Field(default_factory=HttpSettings)
    scan: ScanSettings = Field(default_factory=ScanSettings)
    vulndb: VulnDbSettings = Field(default_factory=VulnDbSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)

    @classmethod
    def load(cls, path: Path | None = None) -> Settings:
        """Load settings from YAML, falling back to defaults.

        Lookup order:
        1. Explicit ``path`` argument
        2. ``WP_SHIELD_CONFIG`` environment variable
        3. ``<config_dir>/config.yaml``
        """
        candidate = path or _env_config_path() or config_path()
        if candidate.exists():
            try:
                raw: dict[str, Any] = yaml.safe_load(candidate.read_text()) or {}
                return cls.model_validate(raw)
            except (yaml.YAMLError, ValueError) as exc:
                raise RuntimeError(f"Invalid config at {candidate}: {exc}") from exc
        return cls()


def _env_config_path() -> Path | None:
    env = os.environ.get("WP_SHIELD_CONFIG")
    return Path(env) if env else None
