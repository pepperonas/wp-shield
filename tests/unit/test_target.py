"""URL normalization."""

from __future__ import annotations

from wp_shield.core.target import host_of, normalize_url


def test_normalize_adds_scheme() -> None:
    assert normalize_url("example.com").startswith("http://example.com")


def test_normalize_keeps_https() -> None:
    assert normalize_url("https://Example.com").startswith("https://example.com")


def test_normalize_strips_fragment() -> None:
    assert "#" not in normalize_url("https://example.com/foo#bar")


def test_host_of() -> None:
    assert host_of("https://example.com:8080/x") == "example.com"
    assert host_of("nothing") == ""
