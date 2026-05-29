"""``checks/xmlrpc`` against mocked HTTP."""

from __future__ import annotations

import httpx
import pytest
import respx

from wp_shield.checks import xmlrpc
from wp_shield.core.http import HttpClient


@pytest.mark.asyncio
@respx.mock
async def test_xmlrpc_active(http_settings) -> None:
    base = "http://wp.test/"
    respx.get("http://wp.test/xmlrpc.php").mock(return_value=httpx.Response(
        405, text="XML-RPC server accepts POST requests only.",
    ))
    respx.post("http://wp.test/xmlrpc.php").mock(return_value=httpx.Response(
        200,
        text='<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
             '<value><string>system.listMethods</string></value>'
             '<value><string>wp.getUsersBlogs</string></value>'
             '</data></array></value></param></params></methodResponse>',
    ))

    async with HttpClient(http_settings) as http:
        findings = await xmlrpc.run(http, base)

    assert any("RPC method" in f.title or "method calls" in f.title for f in findings)


@pytest.mark.asyncio
@respx.mock
async def test_xmlrpc_blocked(http_settings) -> None:
    respx.get("http://wp.test/xmlrpc.php").mock(return_value=httpx.Response(403, text="Forbidden"))
    async with HttpClient(http_settings) as http:
        findings = await xmlrpc.run(http, "http://wp.test/")
    assert findings == []
