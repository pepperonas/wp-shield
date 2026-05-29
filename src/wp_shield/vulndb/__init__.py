"""Local vulnerability database. Default source: WPVulnerability.net (free, no token).

Wordfence v3 (since 2025) requires a Bearer token; we keep it as an optional
source for users who have one.
"""

from .match import find_vulnerabilities
from .store import VulnStore
from .sync import sync_wordfence
from .sync_wpvuln import sync_wpvuln, sync_wpvuln_async

__all__ = [
    "VulnStore",
    "find_vulnerabilities",
    "sync_wordfence",
    "sync_wpvuln",
    "sync_wpvuln_async",
]
