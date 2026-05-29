"""Target URL handling — normalization, reachability, IP resolution."""

from __future__ import annotations

import logging
import socket
from urllib.parse import urlparse, urlunparse

from ..models import TargetInfo
from .http import HttpClient

log = logging.getLogger("wp_shield.target")


def normalize_url(raw: str) -> str:
    """Add a scheme if missing; strip trailing slashes from path root."""
    s = raw.strip()
    if "://" not in s:
        s = "http://" + s
    parsed = urlparse(s)
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def resolve_ip(host: str) -> str | None:
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


async def probe_target(raw: str, http: HttpClient) -> TargetInfo:
    """Resolve + probe a target URL.

    Reaches out once with GET / to determine reachability, final URL after
    redirects, server header and X-Powered-By. WAF detection is done elsewhere
    (``waf.detect``) from the same response if available.
    """
    url = normalize_url(raw)
    host = host_of(url)
    ip = resolve_ip(host)

    info = TargetInfo(raw_input=raw, url=url, host=host, ip=ip)

    resp = await http.get(url)
    if resp is None:
        log.info("Target %s unreachable", url)
        return info

    info.reachable = resp.status_code < 500
    info.final_url = str(resp.url)
    info.server_header = resp.headers.get("server")
    info.powered_by = resp.headers.get("x-powered-by")

    # If GET to http:// redirected to https://, prefer https for future requests.
    if str(resp.url).startswith("https://") and url.startswith("http://"):
        info.url = str(resp.url).rstrip("/") + "/"

    return info
