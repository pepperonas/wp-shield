"""Detect exposed backup / config files in the WordPress webroot.

These are catastrophic when present: ``wp-config.php.bak`` leaks DB
credentials; ``.git/`` exposes the full source-control history; ``.env``
typically contains API keys.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import Confidence, Finding, Severity

# (path, severity, label, description)
_CRITICAL_PATHS: tuple[tuple[str, Severity, str, str], ...] = (
    ("wp-config.php.bak", Severity.CRITICAL, "wp-config.php.bak", "Backup of wp-config.php — contains DB credentials and secret keys."),
    ("wp-config.php.old", Severity.CRITICAL, "wp-config.php.old", "Old copy of wp-config.php — likely contains DB credentials."),
    ("wp-config.php.save", Severity.CRITICAL, "wp-config.php.save", "Crash-recovery copy of wp-config.php — contains DB credentials."),
    ("wp-config.php~", Severity.CRITICAL, "wp-config.php~", "Editor backup of wp-config.php — contains DB credentials."),
    ("wp-config.php.swp", Severity.CRITICAL, "wp-config.php.swp", "Vim swap file for wp-config.php — contains DB credentials."),
    ("wp-config.php_bak", Severity.CRITICAL, "wp-config.php_bak", "Backup copy of wp-config.php."),
    ("wp-config.php.orig", Severity.CRITICAL, "wp-config.php.orig", "Merge backup of wp-config.php."),
    ("wp-config-sample.php", Severity.INFO, "wp-config-sample.php", "Default sample config — not sensitive but suggests fresh install."),
    (".env", Severity.HIGH, ".env file", "Application secrets / API keys are typically stored here."),
    (".git/config", Severity.HIGH, ".git/config", "Public .git directory — full source history is downloadable."),
    (".git/HEAD", Severity.HIGH, ".git/HEAD", "Public .git directory — full source history is downloadable."),
    (".hg/store/00manifest.i", Severity.HIGH, ".hg directory", "Public Mercurial repository in webroot."),
    (".svn/entries", Severity.HIGH, ".svn directory", "Public Subversion working copy in webroot."),
    (".DS_Store", Severity.LOW, ".DS_Store", "macOS metadata file — leaks file names in the directory."),
    ("backup.sql", Severity.CRITICAL, "backup.sql", "SQL database dump — likely contains hashed passwords and full content."),
    ("backup.zip", Severity.HIGH, "backup.zip", "Backup archive in webroot."),
    ("backup.tar.gz", Severity.HIGH, "backup.tar.gz", "Backup archive in webroot."),
    ("site.zip", Severity.HIGH, "site.zip", "Backup archive in webroot."),
    ("dump.sql", Severity.CRITICAL, "dump.sql", "SQL database dump — likely contains hashed passwords and full content."),
    ("wp-content/uploads/wpforms/", Severity.LOW, "wpforms uploads directory", "Form-submission upload directory exposed."),
    ("error_log", Severity.MEDIUM, "PHP error_log", "Server-side error log accessible — may leak code paths and queries."),
    ("phpinfo.php", Severity.HIGH, "phpinfo.php", "phpinfo() output exposed — leaks PHP modules, env vars, paths."),
    ("info.php", Severity.HIGH, "info.php", "Possibly phpinfo() — leaks PHP modules, env vars, paths."),
    ("test.php", Severity.LOW, "test.php", "Stray test file in webroot."),
    ("wp-content/uploads/php.ini", Severity.MEDIUM, "uploaded php.ini", "User-controlled php.ini override in uploads directory."),
)


def _looks_real(body: str, header_content_type: str) -> bool:
    """Heuristic: distinguish a legit hit from a soft-404 / WP catch-all."""
    if not body:
        return True
    body_lower = body[:512].lower()
    # WordPress catch-all 404 will usually be served as text/html with <!DOCTYPE
    if "html" in (header_content_type or "").lower() and "<!doctype html" in body_lower:
        return False
    if "page not found" in body_lower or "nothing found" in body_lower:
        return False
    return True


async def run(http: HttpClient, base_url: str) -> list[Finding]:
    async def probe(path: str, severity: Severity, label: str, desc: str) -> Finding | None:
        url = urljoin(base_url, path)
        resp = await http.get(url)
        if resp is None or resp.status_code != 200:
            return None
        body = ""
        try:
            body = resp.text
        except UnicodeDecodeError:
            body = ""
        if not _looks_real(body, resp.headers.get("content-type", "")):
            return None
        evidence = body[:200] if body else "<binary>"
        return Finding(
            rule_id=f"wp.exposed_file.{path.replace('/', '_').replace('.', '_')}",
            title=f"Exposed file: {label}",
            severity=severity,
            description=desc,
            evidence=evidence,
            location=url,
            remediation="Remove the file from the webroot or block access via a web-server rule.",
            confidence=Confidence.HIGH,
            tags=["exposed-file", "misconfiguration"],
        )

    results = await asyncio.gather(
        *(probe(p, s, label, desc) for p, s, label, desc in _CRITICAL_PATHS)
    )
    return [f for f in results if f is not None]
