"""``wp-shield`` command-line interface."""

from __future__ import annotations

import asyncio
import logging
import sys
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


@app.command("scan")
def cmd_scan(
    target: str = typer.Argument(..., help="Target URL, e.g. https://example.com/"),
    mode: ScanMode = typer.Option(ScanMode.MIXED, "--mode", help="Scan intensity."),
    output: list[str] = typer.Option(
        ["cli"], "--output", "-o", help="Output format(s): cli | json | html | sarif (repeatable)."
    ),
    output_file: Path | None = typer.Option(
        None, "--output-file", "-f", help="Write non-CLI output here. For multiple formats, suffix is appended."
    ),
    no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt (use only on systems you own)."),
    no_vuln_match: bool = typer.Option(False, "--no-vuln-match", help="Skip vulnerability matching."),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to YAML config."),
    timeout: float | None = typer.Option(None, "--timeout", help="Per-request timeout in seconds."),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Max concurrent HTTP requests."),
    rate_limit: float | None = typer.Option(None, "--rate-limit", help="Max requests per second."),
    rotate_ua: bool = typer.Option(False, "--rotate-user-agent", help="Rotate browser user-agents."),
    proxy: str | None = typer.Option(None, "--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)."),
) -> None:
    """Scan a WordPress site."""
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

    non_cli_formats = [f for f in formats if f != "cli"]
    multiple_files = len(non_cli_formats) > 1
    for fmt in non_cli_formats:
        body = reporter.render(result, fmt)
        if body is None:
            continue
        if output_file is None:
            sys.stdout.write(body + "\n")
            continue
        # When several non-CLI formats share one --output-file, suffix each one
        # so we never overwrite. Otherwise honour the caller's path exactly.
        path = output_file.with_suffix(f".{fmt}") if multiple_files else output_file
        path.write_text(body, encoding="utf-8")
        console.print(f"[green]✓[/] Wrote {fmt} report to {path}")


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
