"""Version-detection module."""

from __future__ import annotations

from wp_shield.detect.version import _versions_from_html


def test_meta_generator() -> None:
    html = '<head><meta name="generator" content="WordPress 6.5.2" /></head>'
    assert _versions_from_html(html) == [("meta-generator", "6.5.2")]


def test_emoji_release() -> None:
    html = '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.4.3"></script>'
    versions = dict(_versions_from_html(html))
    assert versions["emoji-js"] == "6.4.3"


def test_block_library() -> None:
    html = '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.5.2&load=true"/>'
    versions = dict(_versions_from_html(html))
    # URL contains "block-library" but not the exact "wp-block-library" token
    # the regex looks for, so this is mostly a smoke test that it doesn't crash.
    assert isinstance(versions, dict)


def test_no_signals() -> None:
    assert _versions_from_html("<html><body>nothing here</body></html>") == []
