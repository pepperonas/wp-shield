"""``wp-shield`` command-line interface."""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from . import __version__
from .core import reporter
from .models import ScanMode
from .scan import scan as run_scan
from .settings import Settings, owned_domains_path
from .vulndb import VulnStore, sync_wordfence, sync_wpvuln

app = typer.Typer(
    name="wp-shield",
    help="WordPress security audit scanner — black-box detection of versions, plugins, themes, users, misconfigurations and known CVEs.",
    add_completion=False,
    no_args_is_help=True,
)
db_app = typer.Typer(name="db", help="Vulnerability database commands.")
app.add_typer(db_app, name="db")

console = Console()
log = logging.getLogger("wp_shield")


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"wp-shield [bold cyan]{__version__}[/]")
        raise typer.Exit()


@app.callback()
def _global_options(
    version: bool | None = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Print version and exit."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose logging."),
) -> None:
    _configure_logging(verbose)


def _safe_host_slug(target_url: str) -> str:
    """Filesystem-safe slug derived from the target host."""
    from urllib.parse import urlparse
    host = urlparse(target_url).hostname or "unknown"
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", host).strip("-") or "unknown"


def _build_scan_dir(base: Path, target_url: str, started_at: datetime) -> Path:
    ts = started_at.strftime("%Y%m%d-%H%M%S")
    return base / f"{ts}_{_safe_host_slug(target_url)}"


@app.command("scan")
def cmd_scan(
    target: str = typer.Argument(..., help="Target URL, e.g. https://example.com/"),
    mode: ScanMode = typer.Option(ScanMode.MIXED, "--mode", help="Scan intensity."),
    output: list[str] = typer.Option(
        ["cli"], "--output", "-o", help="Live output format(s): cli | json | html | sarif (repeatable). Independent of auto-save."
    ),
    output_file: Path | None = typer.Option(
        None, "--output-file", "-f", help="Write the live --output to this path (overrides auto-save location for that one format)."
    ),
    output_dir: Path | None = typer.Option(
        None, "--output-dir", help="Override the directory where every scan is auto-saved (default: ./out)."
    ),
    no_save: bool = typer.Option(False, "--no-save", help="Skip auto-saving HTML+JSON+SARIF to the out directory."),
    open_html: bool = typer.Option(False, "--open", help="Open the auto-saved HTML report in your default browser when done."),
    no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt (use only on systems you own)."),
    no_vuln_match: bool = typer.Option(False, "--no-vuln-match", help="Skip vulnerability matching."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    timeout: float | None = typer.Option(None, "--timeout", help="Per-request timeout in seconds."),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Max concurrent HTTP requests."),
    rate_limit: float | None = typer.Option(None, "--rate-limit", help="Max requests per second."),
    rotate_ua: bool = typer.Option(False, "--rotate-user-agent", help="Rotate browser user-agents."),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)."),
) -> None:
    """Scan a WordPress site.

    By default, every scan auto-saves HTML, JSON and SARIF reports plus a
    snapshot of the CLI render to ``./out/<timestamp>_<host>/``. The live
    ``--output`` flag only controls what is shown / streamed in the terminal.
    Pass ``--no-save`` to disable the on-disk artefact.
    """
    settings = Settings.load(config)
    if no_robots:
        settings.http.respect_robots_txt = False
    if timeout is not None:
        settings.http.timeout = timeout
    if concurrency is not None:
        settings.http.max_concurrency = concurrency
    if rate_limit is not None:
        settings.http.rate_limit_per_second = rate_limit
    if rotate_ua:
        settings.http.rotate_user_agent = True
    if proxy:
        settings.http.proxy = proxy
    if output_dir is not None:
        settings.output.output_dir = output_dir
    if no_save:
        settings.output.auto_save = False

    store: VulnStore | None = None
    if not no_vuln_match:
        store = VulnStore()
        if store.last_sync() is None:
            console.print("[yellow]Warning:[/] Vulnerability DB is empty. Run [bold]wp-shield update[/] first.")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        prog.add_task(description=f"Scanning {target}…", total=None)
        result = asyncio.run(run_scan(target, settings, mode=mode, store=store))

    formats = [f.lower() for f in output]
    if "cli" in formats:
        reporter.render_cli(result, console)

    # --- Explicit --output-file override for the live output --------------
    explicit_targets = [f for f in formats if f != "cli"]
    explicit_multi = len(explicit_targets) > 1
    explicit_paths: dict[str, Path] = {}
    for fmt in explicit_targets:
        body = reporter.render(result, fmt)
        if body is None:
            continue
        if output_file is None:
            # No explicit file — the auto-save block below handles persistence.
            # For non-CLI formats without --output-file we also stream to stdout
            # to preserve the previous behaviour for pipeline users.
            sys.stdout.write(body + "\n")
            continue
        path = output_file.with_suffix(f".{fmt}") if explicit_multi else output_file
        path.write_text(body, encoding="utf-8")
        explicit_paths[fmt] = path
        console.print(f"[green]✓[/] Wrote {fmt} report to {path}")

    # --- Auto-save (default behaviour) ------------------------------------
    if settings.output.auto_save:
        scan_dir = _build_scan_dir(settings.output.output_dir, result.target.url, result.started_at)
        scan_dir.mkdir(parents=True, exist_ok=True)
        saved: dict[str, Path] = {}

        # Snapshot of the live CLI render for the audit trail. We redirect the
        # rendering console to an in-memory buffer so it doesn't echo a second
        # time to the real terminal.
        import io
        cli_buf = io.StringIO()
        cli_console = Console(
            file=cli_buf, record=True, width=120, force_terminal=False, color_system=None,
        )
        reporter.render_cli(result, cli_console)
        (scan_dir / "report.txt").write_text(cli_console.export_text(), encoding="utf-8")
        saved["txt"] = scan_dir / "report.txt"

        for fmt in settings.output.auto_save_formats:
            if fmt in explicit_paths:
                # Caller chose an explicit path; mirror it into out/ for the audit trail.
                pass
            body = reporter.render(result, fmt)
            if body is None:
                continue
            path = scan_dir / f"report.{fmt}"
            path.write_text(body, encoding="utf-8")
            saved[fmt] = path

        rel = scan_dir
        try:
            rel = scan_dir.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            rel = scan_dir.resolve()
        console.print(f"[green]✓[/] Saved {len(saved)} report file(s) to [bold]{rel}/[/]")

        if open_html and "html" in saved:
            import webbrowser
            webbrowser.open(saved["html"].resolve().as_uri())


@app.command("update")
def cmd_update(
    source: str = typer.Option(
        "wpvulnerability",
        "--source",
        help="Vulnerability data source: wpvulnerability (free) | wordfence (token-gated since 2025).",
        case_sensitive=False,
    ),
    feed_url: str | None = typer.Option(None, "--feed-url", help="Override the upstream feed URL (wordfence only)."),
    api_token: str | None = typer.Option(None, "--api-token", envvar="WORDFENCE_API_TOKEN",
                                            help="Wordfence Intelligence Bearer token (required for wordfence)."),
    plugin_limit: int = typer.Option(500, "--plugin-limit",
                                     help="(wpvulnerability) Top-N plugins to pre-warm."),
    theme_limit: int = typer.Option(200, "--theme-limit",
                                    help="(wpvulnerability) Top-N themes to pre-warm."),
    concurrency: int = typer.Option(8, "--concurrency", help="(wpvulnerability) Max concurrent requests."),
) -> None:
    """Download / refresh the local vulnerability database."""
    source = source.lower()
    store = VulnStore()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=False,
    ) as prog:
        task = prog.add_task(f"[cyan]Syncing ({source})…", total=None)

        def on_progress(n: int) -> None:
            prog.update(task, description=f"[cyan]({source}) synced {n:,} records…")

        try:
            if source == "wpvulnerability":
                total = sync_wpvuln(
                    store,
                    plugin_limit=plugin_limit,
                    theme_limit=theme_limit,
                    concurrency=concurrency,
                    on_progress=on_progress,
                )
            elif source == "wordfence":
                from .vulndb.sync import WORDFENCE_FEED_URL
                if not api_token:
                    console.print("[red]✗[/] Wordfence requires --api-token (or env WORDFENCE_API_TOKEN).")
                    raise typer.Exit(code=2)
                url = feed_url or WORDFENCE_FEED_URL
                total = sync_wordfence(store, feed_url=url,
                                       api_token=api_token, on_progress=on_progress)
            else:
                console.print(f"[red]✗[/] Unknown source: {source}")
                raise typer.Exit(code=2)
        except typer.Exit:
            raise
        except Exception as exc:
            console.print(f"[red]✗[/] Sync failed: {exc}")
            raise typer.Exit(code=1) from None

    console.print(f"[green]✓[/] Imported {total:,} vulnerabilities from {source}.")


@db_app.command("stats")
def cmd_db_stats() -> None:
    """Show vulnerability DB statistics."""
    store = VulnStore()
    s = store.stats()
    console.print(f"[bold cyan]wp-shield DB[/] @ {s['db_path']}")
    console.print(f"  total vulnerabilities: [bold]{s['total_vulnerabilities']:,}[/]")
    console.print(f"  by component type    : {s['by_component_type']}")
    console.print(f"  last sync            : {s['last_sync'] or '[red]never[/]'}")


@db_app.command("path")
def cmd_db_path() -> None:
    """Print the local database file path."""
    console.print(str(VulnStore().path))


@app.command("init")
def cmd_init() -> None:
    """Create the config directory + owned-domains stub."""
    path = owned_domains_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(
            "# wp-shield owned-domains allow-list.\n"
            "# Add one domain (or hostname) per line. Only domains listed here may\n"
            "# be subjected to the (planned) brute-force module.\n"
            "# example: my-test-site.local\n",
            encoding="utf-8",
        )
    console.print(f"[green]✓[/] Config dir initialized at {path.parent}")


if __name__ == "__main__":
    app()
