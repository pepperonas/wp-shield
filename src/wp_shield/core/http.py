"""Async HTTP client with retries, rate-limiting, robots.txt, and UA-rotation.

This is the single entry point through which every detection or check module
talks to the target site. Keeping HTTP-policy in one place lets us enforce
"polite scanner" semantics globally.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..settings import HttpSettings

log = logging.getLogger("wp_shield.http")

# Modern, plausible UA list. We default to identifying as wp-shield, but
# rotate_user_agent=True swaps in real-browser strings (useful for WAF testing).
_BROWSER_USER_AGENTS: tuple[str, ...] = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
)


class RateLimiter:
    """Token-bucket-ish limiter — keeps RPS at or below the configured value."""

    def __init__(self, rps: float) -> None:
        self._rps = max(rps, 0.1)
        self._min_interval = 1.0 / self._rps
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last = time.monotonic()


class HttpClient:
    """Thin async wrapper around httpx.AsyncClient with rate-limiting + retries."""

    def __init__(self, settings: HttpSettings, base_url: str | None = None) -> None:
        self._settings = settings
        self._base_url = base_url
        self._semaphore = asyncio.Semaphore(settings.max_concurrency)
        self._rate_limiter = RateLimiter(settings.rate_limit_per_second)
        self._client: httpx.AsyncClient | None = None
        self._robots: dict[str, RobotFileParser] = {}

    @property
    def settings(self) -> HttpSettings:
        return self._settings

    async def __aenter__(self) -> HttpClient:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    async def start(self) -> None:
        if self._client is not None:
            return
        proxy = self._settings.proxy
        proxies: str | None = proxy if proxy else None
        self._client = httpx.AsyncClient(
            timeout=self._settings.timeout,
            verify=self._settings.verify_ssl,
            follow_redirects=self._settings.follow_redirects,
            proxy=proxies,
            http2=True,
            headers={
                "User-Agent": self._pick_ua(initial=True),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _pick_ua(self, initial: bool = False) -> str:
        if self._settings.rotate_user_agent:
            return random.choice(_BROWSER_USER_AGENTS)
        return self._settings.user_agent

    async def _robots_for(self, url: str) -> RobotFileParser | None:
        if not self._settings.respect_robots_txt:
            return None
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._robots:
            rp = RobotFileParser()
            robots_url = urljoin(origin, "/robots.txt")
            try:
                resp = await self._raw_get(robots_url, _bypass_robots=True)
                if resp is not None and resp.status_code == 200:
                    rp.parse(resp.text.splitlines())
                else:
                    rp.parse([])  # empty == allow all
            except (httpx.HTTPError, OSError) as exc:
                log.debug("Could not fetch %s: %s", robots_url, exc)
                rp.parse([])
            self._robots[origin] = rp
        return self._robots[origin]

    async def _check_allowed(self, url: str) -> bool:
        rp = await self._robots_for(url)
        if rp is None:
            return True
        return rp.can_fetch(self._settings.user_agent, url)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        retry=retry_if_exception_type((httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError)),
        reraise=True,
    )
    async def _raw_get(self, url: str, *, _bypass_robots: bool = False, **kwargs: Any) -> httpx.Response | None:
        if self._client is None:
            await self.start()
        assert self._client is not None
        if not _bypass_robots and not await self._check_allowed(url):
            log.info("robots.txt disallows %s", url)
            return None
        await self._rate_limiter.acquire()
        async with self._semaphore:
            headers = kwargs.pop("headers", {}) or {}
            if self._settings.rotate_user_agent:
                headers.setdefault("User-Agent", self._pick_ua())
            return await self._client.get(url, headers=headers, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        """GET with all policies applied. Returns None when robots.txt disallows."""
        try:
            return await self._raw_get(url, **kwargs)
        except httpx.HTTPError as exc:
            log.debug("GET %s failed: %s", url, exc)
            return None

    async def head(self, url: str, **kwargs: Any) -> httpx.Response | None:
        if self._client is None:
            await self.start()
        assert self._client is not None
        if not await self._check_allowed(url):
            return None
        await self._rate_limiter.acquire()
        async with self._semaphore:
            try:
                return await self._client.head(url, **kwargs)
            except httpx.HTTPError as exc:
                log.debug("HEAD %s failed: %s", url, exc)
                return None

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        if self._client is None:
            await self.start()
        assert self._client is not None
        if not await self._check_allowed(url):
            return None
        await self._rate_limiter.acquire()
        async with self._semaphore:
            try:
                return await self._client.post(url, **kwargs)
            except httpx.HTTPError as exc:
                log.debug("POST %s failed: %s", url, exc)
                return None


@asynccontextmanager
async def open_client(settings: HttpSettings) -> AsyncIterator[HttpClient]:
    client = HttpClient(settings)
    await client.start()
    try:
        yield client
    finally:
        await client.aclose()
