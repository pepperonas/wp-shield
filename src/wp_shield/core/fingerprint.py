"""WordPress detection — confirm we're looking at a WP site.

Uses multiple independent signals for confidence. Returns a list of matched
signals (empty == not WordPress).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .http import HttpClient

_WP_PATHS_TO_PROBE: tuple[str, ...] = (
    "wp-login.php",
    "wp-admin/",
    "wp-includes/",
    "readme.html",
    "wp-json/",
    "xmlrpc.php",
)

_WP_HTML_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("meta-generator", re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+wordpress', re.I)),
    ("wp-content-asset", re.compile(r"/wp-content/(?:themes|plugins|uploads)/", re.I)),
    ("wp-includes-asset", re.compile(r"/wp-includes/", re.I)),
    ("wp-json-link", re.compile(r'<link[^>]+rel=["\']https://api\.w\.org/["\']', re.I)),
    ("emoji-release", re.compile(r"wp-emoji-release\.min\.js", re.I)),
    ("wp-block-library", re.compile(r"wp-block-library", re.I)),
)


async def fetch_homepage(http: HttpClient, base_url: str) -> tuple[str, dict[str, str]]:
    """Return (body, headers) of the base URL. Empty body if unreachable."""
    resp = await http.get(base_url)
    if resp is None:
        return "", {}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    try:
        return resp.text, headers
    except UnicodeDecodeError:
        return "", headers


def signals_in_html(html: str) -> list[str]:
    return [name for name, pat in _WP_HTML_PATTERNS if pat.search(html)]


async def probe_known_paths(http: HttpClient, base_url: str) -> list[str]:
    """Quickly probe well-known WordPress paths."""
    signals: list[str] = []
    for path in _WP_PATHS_TO_PROBE:
        url = urljoin(base_url, path)
        resp = await http.head(url)
        if resp is None:
            continue
        if resp.status_code in (200, 401, 403):
            signals.append(f"path:{path}")
        # wp-login.php usually 200 or redirects to it
        if path == "wp-login.php" and resp.status_code in (200, 302):
            signals.append("wp-login-present")
    return signals


async def fingerprint(http: HttpClient, base_url: str) -> tuple[bool, list[str], str]:
    """Return (is_wp, matched_signals, homepage_html).

    The HTML is returned so other detection modules can re-use it without a
    second GET.
    """
    html, _ = await fetch_homepage(http, base_url)
    sig_html = signals_in_html(html)
    sig_paths = await probe_known_paths(http, base_url)
    signals = sig_html + sig_paths

    # Lower bar: any one HTML signal OR two path signals => WordPress.
    is_wp = bool(sig_html) or len(sig_paths) >= 2
    return is_wp, signals, html


def extract_links(html: str) -> list[str]:
    """All <a href> / <link href> / <script src> URLs found in HTML."""
    if not html:
        return []
    soup = BeautifulSoup(html, "lxml")
    urls: list[str] = []
    for tag in soup.find_all(["a", "link"]):
        href = tag.get("href")
        if href:
            urls.append(href)
    for tag in soup.find_all(["script", "img"]):
        src = tag.get("src")
        if src:
            urls.append(src)
    return urls
