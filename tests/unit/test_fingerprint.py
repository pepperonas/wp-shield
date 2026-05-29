"""WordPress fingerprint signals."""

from __future__ import annotations

from wp_shield.core.fingerprint import signals_in_html


def test_meta_generator_detected() -> None:
    html = '<meta name="generator" content="WordPress 6.5.2" />'
    assert "meta-generator" in signals_in_html(html)


def test_wp_content_asset_detected() -> None:
    html = '<link href="/wp-content/themes/astra/style.css">'
    assert "wp-content-asset" in signals_in_html(html)


def test_wp_includes_detected() -> None:
    html = '<script src="/wp-includes/js/wp-emoji-release.min.js"></script>'
    sigs = signals_in_html(html)
    assert "wp-includes-asset" in sigs
    assert "emoji-release" in sigs


def test_non_wordpress() -> None:
    html = "<html><body><h1>Just static HTML</h1></body></html>"
    assert signals_in_html(html) == []


def test_wp_json_link_detected() -> None:
    html = '<link rel="https://api.w.org/" href="https://example.com/wp-json/" />'
    assert "wp-json-link" in signals_in_html(html)
