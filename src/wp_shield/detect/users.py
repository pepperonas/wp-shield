"""User enumeration via multiple WordPress quirks.

Methods (in order):
1. REST endpoint ``/wp-json/wp/v2/users`` — returns id + slug + display name when public
2. ``/?author=<N>`` redirects to ``/author/<slug>/`` for valid IDs
3. oEmbed ``/wp-json/oembed/1.0/embed?url=...`` may leak author display name
4. ``/wp-sitemap-users-1.xml`` lists user slugs on modern WP

Each method is best-effort; the final list is de-duplicated by ``slug``.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin

from ..core.http import HttpClient
from ..models import User

_AUTHOR_PATH_RE = re.compile(r"/author/([a-z0-9._-]+)/?", re.I)
_AUTHOR_SLUG_RE = re.compile(r"/author/([a-z0-9._-]+)/?", re.I)


async def _via_rest(http: HttpClient, base_url: str) -> list[User]:
    """REST API: GET /wp-json/wp/v2/users — may be open."""
    url = urljoin(base_url, "wp-json/wp/v2/users?per_page=100")
    resp = await http.get(url)
    if resp is None or resp.status_code != 200:
        return []
    try:
        data: Any = resp.json()
    except ValueError:
        return []
    if not isinstance(data, list):
        return []
    users: list[User] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        users.append(
            User(
                id=entry.get("id"),
                slug=entry.get("slug"),
                display_name=entry.get("name"),
                detection_methods=["wp-json/users"],
            )
        )
    return users


async def _via_author_id(http: HttpClient, base_url: str, max_id: int) -> list[User]:
    """``?author=N`` redirects to ``/author/<slug>/`` for valid users."""
    async def probe(uid: int) -> User | None:
        url = urljoin(base_url, f"?author={uid}")
        resp = await http.get(url)
        if resp is None:
            return None
        final = str(resp.url)
        if m := _AUTHOR_SLUG_RE.search(final):
            return User(
                id=uid,
                slug=m.group(1),
                detection_methods=["author-id-redirect"],
            )
        # Some sites don't redirect but embed /author/<slug>/ in HTML
        body = resp.text[:8000]
        if m := _AUTHOR_PATH_RE.search(body):
            return User(
                id=uid,
                slug=m.group(1),
                detection_methods=["author-id-html"],
            )
        return None

    results = await asyncio.gather(*(probe(i) for i in range(1, max_id + 1)))
    return [u for u in results if u is not None]


async def _via_user_sitemap(http: HttpClient, base_url: str) -> list[User]:
    """Modern WP: /wp-sitemap-users-1.xml lists user profile URLs."""
    url = urljoin(base_url, "wp-sitemap-users-1.xml")
    resp = await http.get(url)
    if resp is None or resp.status_code != 200:
        return []
    body = resp.text
    users: list[User] = []
    for slug in {m.group(1) for m in _AUTHOR_SLUG_RE.finditer(body)}:
        users.append(User(slug=slug, detection_methods=["user-sitemap"]))
    return users


async def _via_oembed(http: HttpClient, base_url: str) -> list[User]:
    """oEmbed sometimes leaks the author_name for the homepage."""
    embed_url = urljoin(base_url, f"wp-json/oembed/1.0/embed?url={base_url}")
    resp = await http.get(embed_url)
    if resp is None or resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    name = data.get("author_name")
    if not name:
        return []
    return [User(display_name=str(name), detection_methods=["oembed"])]


def _dedup(users: list[User]) -> list[User]:
    """De-duplicate by (id, slug, display_name) while merging detection methods."""
    by_key: dict[tuple[Any, Any, Any], User] = {}
    for u in users:
        key = (u.id, u.slug, u.display_name)
        if key in by_key:
            existing = by_key[key]
            for m in u.detection_methods:
                if m not in existing.detection_methods:
                    existing.detection_methods.append(m)
        else:
            by_key[key] = u
    # Cross-merge: same slug, missing id <-> known id
    by_slug: dict[str, User] = {}
    extras: list[User] = []
    for u in by_key.values():
        if u.slug:
            if u.slug in by_slug:
                target = by_slug[u.slug]
                target.id = target.id or u.id
                target.display_name = target.display_name or u.display_name
                for m in u.detection_methods:
                    if m not in target.detection_methods:
                        target.detection_methods.append(m)
            else:
                by_slug[u.slug] = u
        else:
            extras.append(u)
    return list(by_slug.values()) + extras


async def enumerate_users(
    http: HttpClient,
    base_url: str,
    max_users_to_probe: int = 20,
) -> list[User]:
    rest, sitemap, oembed = await asyncio.gather(
        _via_rest(http, base_url),
        _via_user_sitemap(http, base_url),
        _via_oembed(http, base_url),
    )
    author = await _via_author_id(http, base_url, max_users_to_probe)
    return _dedup(rest + sitemap + oembed + author)
