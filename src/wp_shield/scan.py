"""Top-level scan orchestrator.

Pulls together fingerprinting, enumeration, misconfiguration checks, and
vuln-DB matching. Returns a fully populated ``ScanResult``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from . import __version__
from .checks import (
    debug_log,
    directory_listing,
    readme_exposed,
    registration,
    security_headers,
    wp_cron,
    xmlrpc,
)
from .core import waf
from .core.fingerprint import fingerprint
from .core.http import open_client
from .core.target import probe_target
from .detect import config_files
from .detect.plugins import enumerate_plugins
from .detect.themes import enumerate_themes
from .detect.users import enumerate_users
from .detect.version import detect_version
from .models import Component, ScanMode, ScanResult, Severity
from .settings import Settings
from .vulndb import VulnStore, find_vulnerabilities

log = logging.getLogger("wp_shield.scan")


def _attach_vulnerabilities(components: list[Component], store: VulnStore) -> int:
    total = 0
    for c in components:
        try:
            vulns = find_vulnerabilities(store, c)
            c.vulnerabilities = vulns
            total += len(vulns)
        except Exception as exc:
            log.warning("vuln-match failed for %s/%s: %s", c.type.value, c.slug, exc)
    return total


async def scan(
    raw_target: str,
    settings: Settings,
    *,
    mode: ScanMode | None = None,
    match_vulnerabilities: bool | None = None,
    store: VulnStore | None = None,
) -> ScanResult:
    mode = mode or settings.scan.default_mode
    match = settings.scan.match_vulnerabilities if match_vulnerabilities is None else match_vulnerabilities

    started = datetime.now(UTC)

    async with open_client(settings.http) as http:
        target_info = await probe_target(raw_target, http)
        result = ScanResult(
            target=target_info,
            started_at=started,
            mode=mode,
            tool={"name": "wp-shield", "version": __version__},
        )

        if not target_info.reachable:
            result.errors.append(f"Target {target_info.url} is unreachable")
            result.finished_at = datetime.now(UTC)
            return result

        # Single GET that we'll reuse: fingerprint + WAF + plugin/theme extraction
        is_wp, signals, html = await fingerprint(http, target_info.url)
        result.is_wordpress = is_wp
        result.wp_detection_signals = signals

        # WAF detection (best-effort from the homepage GET we already did inside fingerprint)
        # We re-issue a HEAD just to grab headers without re-downloading the body.
        head_resp = await http.head(target_info.url)
        if head_resp is not None:
            result.target.waf = waf.detect_from_response(head_resp)

        if not is_wp:
            result.errors.append("Target does not appear to be running WordPress")
            result.finished_at = datetime.now(UTC)
            return result

        # --- enumeration & checks run concurrently ---------------------------
        core_task = asyncio.create_task(detect_version(http, target_info.url, html))
        plugins_task = asyncio.create_task(
            enumerate_plugins(
                http,
                target_info.url,
                html,
                mode=mode,
                wordlist_limit=settings.scan.plugin_wordlist_limit,
            )
            if settings.scan.enumerate_plugins
            else _noop_list()
        )
        themes_task = asyncio.create_task(
            enumerate_themes(http, target_info.url, html, mode=mode)
            if settings.scan.enumerate_themes
            else _noop_list()
        )
        users_task = asyncio.create_task(
            enumerate_users(http, target_info.url, settings.scan.max_users_to_probe)
            if settings.scan.enumerate_users
            else _noop_list()
        )

        check_tasks: list[asyncio.Task] = []
        if settings.scan.check_misconfigurations:
            for module in (xmlrpc, wp_cron, registration, readme_exposed,
                           directory_listing, debug_log, security_headers):
                check_tasks.append(asyncio.create_task(module.run(http, target_info.url)))
        if settings.scan.check_config_backups:
            check_tasks.append(asyncio.create_task(config_files.run(http, target_info.url)))

        core_comp = await core_task
        result.components.append(core_comp)
        result.components.extend(await plugins_task)
        result.components.extend(await themes_task)
        result.users = await users_task

        for t in check_tasks:
            try:
                findings = await t
                result.findings.extend(findings)
            except Exception as exc:
                result.errors.append(f"check error: {exc!r}")

    # Vuln matching (sync — SQLite)
    if match and store is not None:
        total = _attach_vulnerabilities(result.components, store)
        log.info("Matched %d vulnerabilities", total)

    # Sort findings by severity for deterministic output
    result.findings.sort(key=lambda f: -Severity(f.severity).numeric)
    result.finished_at = datetime.now(UTC)
    return result


async def _noop_list() -> list:
    return []
