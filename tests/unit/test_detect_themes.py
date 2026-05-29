"""Theme style.css header parsing."""

from __future__ import annotations

from wp_shield.detect.themes import parse_style_header, slugs_in_html


def test_slugs_in_html_themes() -> None:
    html = """
    <link rel='stylesheet' href='/wp-content/themes/twentytwentyfour/style.css?ver=1.0' />
    <link rel='stylesheet' href='/wp-content/themes/astra/css/main.min.css?ver=4.0.0' />
    """
    assert slugs_in_html(html) == {"twentytwentyfour", "astra"}


def test_parse_style_header() -> None:
    css = """/*
    Theme Name: My Theme
    Theme URI: https://example.com/
    Author: Jane Doe
    Author URI: https://example.com/
    Description: A test theme
    Version: 1.2.3
    License: GPL-2.0
    */
    body { color: red; }
    """
    fields = parse_style_header(css)
    assert fields["theme_name"] == "My Theme"
    assert fields["version"] == "1.2.3"
    assert fields["author"] == "Jane Doe"


def test_parse_style_header_no_header() -> None:
    fields = parse_style_header("body { color: red; }")
    assert fields == {}
