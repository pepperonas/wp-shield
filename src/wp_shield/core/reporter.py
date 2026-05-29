"""Render :class:`ScanResult` in multiple formats: CLI, JSON, HTML, SARIF."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from html import escape
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..models import ScanResult, Severity

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bright_red",
    Severity.CRITICAL: "bold red on white",
}

# ---------------------------------------------------------------- CLI (Rich)


def render_cli(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    header = Text()
    header.append("wp-shield ", style="bold cyan")
    header.append(f"v{__version__} ", style="dim")
    header.append(f"  target: {result.target.url}", style="bold")
    if result.target.ip:
        header.append(f"  ({result.target.ip})", style="dim")
    console.print(Panel(header, border_style="cyan"))

    if not result.is_wordpress:
        console.print("[bold yellow]Target does not appear to be running WordPress.[/]")
        if result.errors:
            for e in result.errors:
                console.print(f"  [red]•[/] {e}")
        return

    # ------------ summary
    sev = result.severity_counts()
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Mode:", result.mode.value)
    summary.add_row("WP signals:", ", ".join(result.wp_detection_signals[:6]) or "-")
    if result.target.waf:
        summary.add_row("WAF/CDN:", result.target.waf)
    if result.core:
        v = result.core.version or "(unknown)"
        summary.add_row("Core version:", f"{v}  (confidence: {result.core.confidence.value})")
    summary.add_row("Plugins detected:", str(len(result.plugins)))
    summary.add_row("Themes detected:", str(len(result.themes)))
    summary.add_row("Users discovered:", str(len(result.users)))
    summary.add_row("Findings:", str(len(result.findings)))
    summary.add_row(
        "Known vulnerabilities:",
        " ".join(f"[{_SEVERITY_STYLE[s]}]{s.value}={sev[s.value]}[/]" for s in Severity if sev[s.value]) or "0",
    )
    if result.duration_seconds is not None:
        summary.add_row("Duration:", f"{result.duration_seconds:.1f}s")
    console.print(Panel(summary, title="Summary", border_style="green"))

    # ------------ components
    if result.components:
        ctable = Table(title="Components", show_lines=False, header_style="bold magenta")
        ctable.add_column("Type", style="cyan")
        ctable.add_column("Slug", style="bold")
        ctable.add_column("Version")
        ctable.add_column("Conf.")
        ctable.add_column("CVEs", justify="right")
        for c in result.components:
            cves = len(c.vulnerabilities)
            cve_cell = f"[red]{cves}[/]" if cves else "0"
            ctable.add_row(
                c.type.value,
                c.slug,
                c.version or "-",
                c.confidence.value,
                cve_cell,
            )
        console.print(ctable)

    # ------------ vulnerabilities
    vulns_present = any(c.vulnerabilities for c in result.components)
    if vulns_present:
        vtable = Table(title="Known Vulnerabilities (matched against local DB)", header_style="bold red")
        vtable.add_column("Severity")
        vtable.add_column("Component", style="cyan")
        vtable.add_column("CVE", style="magenta")
        vtable.add_column("Title")
        for c in result.components:
            for v in c.vulnerabilities:
                cve = ", ".join(v.cve_ids[:2]) or "-"
                vtable.add_row(
                    f"[{_SEVERITY_STYLE[v.severity]}]{v.severity.value.upper()}[/]",
                    f"{c.type.value}:{c.slug}@{c.version or '?'}",
                    cve,
                    (v.title or "")[:80],
                )
        console.print(vtable)

    # ------------ users
    if result.users:
        utable = Table(title="Users", header_style="bold cyan")
        utable.add_column("ID")
        utable.add_column("Slug")
        utable.add_column("Display name")
        utable.add_column("Found via", style="dim")
        for u in result.users:
            utable.add_row(
                str(u.id) if u.id is not None else "-",
                u.slug or "-",
                u.display_name or "-",
                ",".join(u.detection_methods),
            )
        console.print(utable)

    # ------------ findings
    if result.findings:
        ftable = Table(title="Findings", header_style="bold yellow")
        ftable.add_column("Severity")
        ftable.add_column("Rule")
        ftable.add_column("Title")
        ftable.add_column("Location", style="dim")
        for f in result.findings:
            ftable.add_row(
                f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value.upper()}[/]",
                f.rule_id,
                f.title,
                (f.location or "")[:60],
            )
        console.print(ftable)

    if result.errors:
        console.print(Panel("\n".join(result.errors), title="Errors", border_style="red"))


# ---------------------------------------------------------------- JSON


def render_json(result: ScanResult, indent: int = 2) -> str:
    return result.to_json(indent=indent)


# ---------------------------------------------------------------- HTML


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>wp-shield report — {target}</title>
<style>
  :root {{ --bg:#0e1116; --panel:#161b22; --fg:#c9d1d9; --muted:#8b949e;
           --info:#79b8ff; --low:#56d4dd; --med:#e3b341; --high:#ff7b72;
           --crit:#ff4d4d; --bd:#30363d; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
          background:var(--bg); color:var(--fg); }}
  header {{ padding:24px 32px; border-bottom:1px solid var(--bd); background:#0a0d12; }}
  h1 {{ margin:0 0 4px; font-size:22px; }}
  h2 {{ margin:32px 32px 12px; font-size:18px; border-left:3px solid var(--info); padding-left:10px; }}
  main {{ padding:0 32px 60px; }}
  .row {{ display:flex; flex-wrap:wrap; gap:24px; margin:16px 32px; }}
  .card {{ flex:1 1 220px; background:var(--panel); border:1px solid var(--bd); border-radius:8px; padding:14px 18px; }}
  .card b {{ display:block; color:var(--muted); font-weight:500; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
  .card span {{ font-size:20px; }}
  table {{ width:calc(100% - 64px); margin:0 32px; border-collapse:collapse;
           background:var(--panel); border:1px solid var(--bd); border-radius:8px; overflow:hidden; }}
  th, td {{ padding:9px 12px; text-align:left; border-bottom:1px solid var(--bd); vertical-align:top; }}
  th {{ background:#0d1117; color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }}
  tr:last-child td {{ border-bottom:none; }}
  .sev {{ display:inline-block; padding:2px 8px; border-radius:99px; font-size:11px; font-weight:700; letter-spacing:.05em; text-transform:uppercase; }}
  .sev.info {{ background:rgba(121,184,255,.18); color:var(--info); }}
  .sev.low  {{ background:rgba(86,212,221,.18); color:var(--low); }}
  .sev.medium {{ background:rgba(227,179,65,.20); color:var(--med); }}
  .sev.high {{ background:rgba(255,123,114,.20); color:var(--high); }}
  .sev.critical {{ background:rgba(255,77,77,.25); color:var(--crit); }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }}
  .meta {{ color:var(--muted); font-size:12px; }}
  .empty {{ color:var(--muted); margin:0 32px; }}
  footer {{ margin-top:60px; padding:18px 32px; border-top:1px solid var(--bd); color:var(--muted); font-size:12px; }}
</style></head>
<body>
<header>
  <h1>wp-shield report</h1>
  <div class="meta">{target} · scanned {scanned_at} · mode {mode} · v{version}</div>
</header>
<main>
  <div class="row">
    <div class="card"><b>WordPress detected</b><span>{is_wp}</span></div>
    <div class="card"><b>Core version</b><span>{core_version}</span></div>
    <div class="card"><b>Plugins</b><span>{plugin_count}</span></div>
    <div class="card"><b>Themes</b><span>{theme_count}</span></div>
    <div class="card"><b>Users</b><span>{user_count}</span></div>
    <div class="card"><b>Vulnerabilities</b><span>{vuln_count}</span></div>
  </div>

  <h2>Components</h2>
  {components_table}

  <h2>Vulnerabilities</h2>
  {vulns_table}

  <h2>Findings</h2>
  {findings_table}

  <h2>Users</h2>
  {users_table}
</main>
<footer>
  Generated by wp-shield v{version}. Vulnerability data: Wordfence Intelligence Production Feed.
  This report is for authorized security testing only.
</footer>
</body></html>
"""


def _sev_pill(sev: Severity) -> str:
    return f'<span class="sev {sev.value}">{sev.value}</span>'


def _table_or_empty(rows: list[str], headers: list[str], empty_msg: str) -> str:
    if not rows:
        return f'<p class="empty">{empty_msg}</p>'
    head = "<tr>" + "".join(f"<th>{escape(h)}</th>" for h in headers) + "</tr>"
    return f"<table>{head}{''.join(rows)}</table>"


def render_html(result: ScanResult) -> str:
    # Components table
    rows = []
    for c in result.components:
        cves = len(c.vulnerabilities)
        rows.append(
            "<tr>"
            f"<td>{escape(c.type.value)}</td>"
            f"<td><code>{escape(c.slug)}</code></td>"
            f"<td>{escape(c.version or '-')}</td>"
            f"<td>{escape(c.confidence.value)}</td>"
            f"<td>{cves}</td>"
            "</tr>"
        )
    components_table = _table_or_empty(rows, ["Type", "Slug", "Version", "Confidence", "CVEs"], "No components detected.")

    # Vulnerabilities table
    rows = []
    for c in result.components:
        for v in c.vulnerabilities:
            cve = escape(", ".join(v.cve_ids[:3]) or "-")
            refs = "".join(
                f'<a href="{escape(r)}" rel="noopener" target="_blank">link</a> '
                for r in (v.references or [])[:3]
            )
            rows.append(
                "<tr>"
                f"<td>{_sev_pill(v.severity)}</td>"
                f"<td><code>{escape(c.type.value)}:{escape(c.slug)}@{escape(c.version or '?')}</code></td>"
                f"<td>{cve}</td>"
                f"<td>{escape(v.title)}<div class='meta'>{refs}</div></td>"
                "</tr>"
            )
    vulns_table = _table_or_empty(rows, ["Severity", "Component", "CVE", "Title"], "No known vulnerabilities matched.")

    # Findings table
    rows = []
    for f in result.findings:
        ev = escape(f.evidence[:200]) if f.evidence else ""
        rows.append(
            "<tr>"
            f"<td>{_sev_pill(f.severity)}</td>"
            f"<td><code>{escape(f.rule_id)}</code></td>"
            f"<td>{escape(f.title)}<div class='meta'>{escape(f.description or '')}</div>"
            f"{('<pre>' + ev + '</pre>') if ev else ''}</td>"
            f"<td><code>{escape(f.location or '')}</code></td>"
            "</tr>"
        )
    findings_table = _table_or_empty(rows, ["Severity", "Rule", "Detail", "Location"], "No findings.")

    # Users
    rows = []
    for u in result.users:
        rows.append(
            "<tr>"
            f"<td>{u.id if u.id is not None else '-'}</td>"
            f"<td><code>{escape(u.slug or '-')}</code></td>"
            f"<td>{escape(u.display_name or '-')}</td>"
            f"<td>{escape(', '.join(u.detection_methods))}</td>"
            "</tr>"
        )
    users_table = _table_or_empty(rows, ["ID", "Slug", "Display Name", "Found via"], "No users discovered.")

    return _HTML_TEMPLATE.format(
        target=escape(result.target.url),
        scanned_at=result.started_at.isoformat(timespec="seconds"),
        mode=escape(result.mode.value),
        version=escape(__version__),
        is_wp="yes" if result.is_wordpress else "no",
        core_version=escape((result.core.version if result.core else None) or "-"),
        plugin_count=len(result.plugins),
        theme_count=len(result.themes),
        user_count=len(result.users),
        vuln_count=result.total_vulnerabilities,
        components_table=components_table,
        vulns_table=vulns_table,
        findings_table=findings_table,
        users_table=users_table,
    )


# ---------------------------------------------------------------- SARIF 2.1.0


def render_sarif(result: ScanResult) -> str:
    """Emit a SARIF 2.1.0 report (consumable by GitHub Code Scanning)."""
    # Build rules from rule_ids
    rule_set: dict[str, dict[str, Any]] = {}
    for f in result.findings:
        rule_set.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.title[:120]},
            "fullDescription": {"text": (f.description or f.title)[:1000]},
            "defaultConfiguration": {"level": f.severity.sarif_level},
            "helpUri": f.references[0] if f.references else None,
        })
    for c in result.components:
        for v in c.vulnerabilities:
            rid = f"vuln.{v.uuid}"
            rule_set.setdefault(rid, {
                "id": rid,
                "name": v.title[:120],
                "shortDescription": {"text": v.title[:120]},
                "fullDescription": {"text": (v.description or v.title)[:1000]},
                "defaultConfiguration": {"level": v.severity.sarif_level},
                "properties": {"cve": v.cve_ids, "cvss": v.cvss_score, "source": v.source},
                "helpUri": v.references[0] if v.references else None,
            })

    rules = list(rule_set.values())

    # Build results
    sarif_results: list[dict[str, Any]] = []
    for f in result.findings:
        sarif_results.append({
            "ruleId": f.rule_id,
            "level": f.severity.sarif_level,
            "message": {"text": f.description or f.title},
            "locations": [
                {"physicalLocation": {
                    "artifactLocation": {"uri": f.location or result.target.url},
                }}
            ],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "tags": f.tags,
            },
        })
    for c in result.components:
        for v in c.vulnerabilities:
            sarif_results.append({
                "ruleId": f"vuln.{v.uuid}",
                "level": v.severity.sarif_level,
                "message": {"text": f"{v.title} ({c.type.value}:{c.slug}@{c.version or '?'})"},
                "locations": [
                    {"physicalLocation": {
                        "artifactLocation": {"uri": c.location or result.target.url},
                    }}
                ],
                "properties": {
                    "component_type": c.type.value,
                    "component_slug": c.slug,
                    "component_version": c.version,
                    "cve": v.cve_ids,
                    "cvss": v.cvss_score,
                },
            })

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wp-shield",
                        "version": __version__,
                        "informationUri": "https://github.com/pepperonas/wp-shield",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not bool(result.errors),
                        "startTimeUtc": result.started_at.isoformat(timespec="seconds"),
                        "endTimeUtc": (result.finished_at or datetime.now(UTC)).isoformat(timespec="seconds"),
                    }
                ],
                "results": sarif_results,
                "properties": {
                    "target_url": result.target.url,
                    "is_wordpress": result.is_wordpress,
                    "mode": result.mode.value,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------- Dispatcher


def render(result: ScanResult, fmt: str) -> str | None:
    fmt = fmt.lower()
    if fmt == "json":
        return render_json(result)
    if fmt == "html":
        return render_html(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "cli":
        render_cli(result)
        return None
    raise ValueError(f"Unknown output format: {fmt}")
