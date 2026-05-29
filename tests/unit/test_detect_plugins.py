"""Plugin slug extraction."""

from __future__ import annotations

from wp_shield.detect.plugins import slugs_in_html


def test_slugs_in_html() -> None:
    html = """
    <link rel='stylesheet' href='/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.5.0'>
    <script src='/wp-content/plugins/woocommerce/assets/js/frontend/woocommerce.min.js?ver=6.5'></script>
    <img src='/wp-content/plugins/yoast-seo/admin/icon.svg'>
    <div data-bg="/wp-content/plugins/wpforms-lite/build/assets/img/icon.svg">x</div>
    """
    slugs = slugs_in_html(html)
    assert "elementor" in slugs
    assert "woocommerce" in slugs
    assert "yoast-seo" in slugs
    assert "wpforms-lite" in slugs


def test_slugs_dedupes_and_lowercases() -> None:
    html = """
    /wp-content/plugins/Akismet/aks.js
    /wp-content/plugins/akismet/aks.css
    /wp-content/plugins/AKISMET/file.png
    """
    slugs = slugs_in_html(html)
    assert slugs == {"akismet"}
