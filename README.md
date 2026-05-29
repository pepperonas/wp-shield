# wp-shield

**WordPress security audit scanner** — a clean-room, open-source alternative to [WPScan](https://wpscan.com/), built for legitimate black-box security audits of WordPress installations you own or are authorized to test.

<p>
  <!-- core project meta -->
  <a href="https://github.com/pepperonas/wp-shield/blob/main/LICENSE"><img alt="License: GPL-3.0-or-later" src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white">
  <img alt="Status: Beta" src="https://img.shields.io/badge/status-beta-yellow.svg">
  <img alt="Version 0.1.0" src="https://img.shields.io/badge/version-0.1.0-success.svg">
  <img alt="Platform: macOS · Linux · Raspberry Pi" src="https://img.shields.io/badge/platform-macOS%20%C2%B7%20Linux%20%C2%B7%20Raspberry%20Pi-lightgrey.svg">
</p>

<p>
  <!-- tooling -->
  <img alt="Built with httpx" src="https://img.shields.io/badge/async-httpx-005571.svg">
  <img alt="Typer CLI" src="https://img.shields.io/badge/CLI-Typer-009688.svg">
  <img alt="Pydantic v2" src="https://img.shields.io/badge/models-Pydantic%20v2-E92063.svg?logo=pydantic&logoColor=white">
  <img alt="SQLite" src="https://img.shields.io/badge/storage-SQLite-003B57.svg?logo=sqlite&logoColor=white">
  <img alt="Linter: Ruff" src="https://img.shields.io/badge/linter-Ruff-D7FF64.svg?logo=ruff&logoColor=black">
  <img alt="Tests: pytest" src="https://img.shields.io/badge/tests-pytest-0A9EDC.svg?logo=pytest&logoColor=white">
  <img alt="Output: SARIF 2.1.0" src="https://img.shields.io/badge/output-SARIF%202.1.0-1f6feb.svg">
</p>

<p>
  <!-- dynamic GitHub badges (populate once the repo is public + has activity) -->
  <a href="https://github.com/pepperonas/wp-shield/actions/workflows/test.yml"><img alt="CI" src="https://github.com/pepperonas/wp-shield/actions/workflows/test.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/pepperonas/wp-shield/commits/main"><img alt="Last commit" src="https://img.shields.io/github/last-commit/pepperonas/wp-shield.svg"></a>
  <a href="https://github.com/pepperonas/wp-shield/issues"><img alt="Open issues" src="https://img.shields.io/github/issues/pepperonas/wp-shield.svg"></a>
  <a href="https://github.com/pepperonas/wp-shield/pulls"><img alt="Open PRs" src="https://img.shields.io/github/issues-pr/pepperonas/wp-shield.svg"></a>
  <a href="https://github.com/pepperonas/wp-shield/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/pepperonas/wp-shield.svg?style=social"></a>
  <a href="https://github.com/pepperonas/wp-shield/network/members"><img alt="GitHub forks" src="https://img.shields.io/github/forks/pepperonas/wp-shield.svg?style=social"></a>
  <img alt="Repo size" src="https://img.shields.io/github/repo-size/pepperonas/wp-shield.svg">
  <img alt="Code size" src="https://img.shields.io/github/languages/code-size/pepperonas/wp-shield.svg">
  <img alt="Top language" src="https://img.shields.io/github/languages/top/pepperonas/wp-shield.svg">
  <img alt="Contributors" src="https://img.shields.io/github/contributors/pepperonas/wp-shield.svg">
  <a href="CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
  <a href="https://github.com/pepperonas/wp-shield/blob/main/CHANGELOG.md"><img alt="Keep a Changelog" src="https://img.shields.io/badge/changelog-keep%20a%20changelog-orange.svg"></a>
  <img alt="Conventional Commits" src="https://img.shields.io/badge/commits-conventional-FE5196.svg?logo=conventionalcommits&logoColor=white">
</p>

<p>
  <!-- domain badges -->
  <img alt="Made for WordPress" src="https://img.shields.io/badge/made%20for-WordPress-21759B.svg?logo=wordpress&logoColor=white">
  <img alt="Vuln source: WPVulnerability.net" src="https://img.shields.io/badge/vuln%20source-WPVulnerability.net-darkgreen.svg">
  <img alt="Optional: Wordfence v3" src="https://img.shields.io/badge/optional-Wordfence%20v3-FA0F00.svg">
  <img alt="OWASP-aligned" src="https://img.shields.io/badge/OWASP-aligned-000000.svg">
  <img alt="Authorized-use only" src="https://img.shields.io/badge/use-authorized%20targets%20only-red.svg">
</p>

```
                          _     _      _     _
__      ___ __        ___| |__ (_) ___| | __| |
\ \ /\ / / '_ \ _____/ __| '_ \| |/ _ \ |/ _` |
 \ V  V /| |_) |____\__ \ | | | |  __/ | (_| |
  \_/\_/ | .__/     |___/_| |_|_|\___|_|\__,_|
         |_|
```

## Features (v0.1)

- **Component enumeration** — WordPress core version, plugins, themes, users
- **Misconfiguration detection** — exposed `wp-config.php` backups, debug logs, directory listings, dangerous xmlrpc/wp-cron exposure, missing security headers, open registration
- **CVE matching** — local SQLite cache of the [WPVulnerability.net](https://www.wpvulnerability.net/) feed (free, no API key, no commercial fee). Wordfence Intelligence v3 is supported as an opt-in source if you have a Bearer token (their previously-free v1/v2 endpoints returned HTTP 410 Gone in 2025).
- **Multi-format reports** — CLI tables (Rich), JSON, standalone HTML, SARIF 2.1.0 (GitHub Code Scanning)
- **Polite by default** — respects `robots.txt`, rate-limited, identifies as `wp-shield/0.1` user-agent

## Roadmap

- v0.2: Web dashboard (FastAPI + HTMX), scheduled scans
- v0.3: Headless Chromium mode (Playwright) for SPA WordPress sites
- v0.4: Opt-in authentication-stress module (gated by owned-domains allow-list)

## Installation

```bash
pip install wp-shield
# or for development:
git clone https://github.com/pepperonas/wp-shield.git
cd wp-shield
pip install -e ".[dev]"
```

## Quickstart

```bash
# 1) Sync the local vulnerability database (~once per day, default source: WPVulnerability)
wp-shield update                # default: source=wpvulnerability, plugin_limit=500, theme_limit=200
# or for Wordfence Intelligence (requires Bearer token):
# WORDFENCE_API_TOKEN=xxx wp-shield update --source wordfence

# 2) Run a scan — auto-saves report.{html,json,sarif,txt} into ./out/<timestamp>_<host>/
wp-shield scan https://example.com

# 3) Same scan but also open the HTML report in your browser when done
wp-shield scan https://example.com --open

# 4) Skip the on-disk artefact (CLI-only)
wp-shield scan https://example.com --no-save

# 5) Stream JSON to stdout (useful in pipelines)
wp-shield scan https://example.com --output json --no-save

# 6) Custom output directory (also configurable via config.yaml)
wp-shield scan https://example.com --output-dir /var/lib/wp-shield/scans

# 7) Database stats
wp-shield db stats
```

### Auto-save layout

Every scan creates a timestamped subdirectory inside `out/` (or your
configured `output.output_dir`):

```
out/
└── 20260529-185717_wpvulnerability.com/
    ├── report.txt    # ANSI-stripped Rich CLI snapshot — audit-trail friendly
    ├── report.html   # standalone styled report (open in browser)
    ├── report.json   # full Pydantic dump (machine-readable)
    └── report.sarif  # SARIF 2.1.0 — upload to GitHub Code Scanning
```

`out/` is in `.gitignore` by default so scan artefacts never get committed.

### One-liner: live demo against a public WordPress site

```bash
cd /Users/martin/claude/wp-shield && source .venv/bin/activate && \
  wp-shield scan https://wpvulnerability.com/ --mode mixed --rate-limit 3 --open
```

This runs a polite mixed-mode scan, prints the live Rich table, writes all
four report formats into `out/<timestamp>_wpvulnerability.com/`, and opens
the HTML report in your default browser.

> `wpvulnerability.com/` is used as the demo target because its maintainer publishes the very vulnerability data this tool consumes — it is an explicitly invited test surface. Replace the URL with **any system you own or have written authorization to test**.

## Detection Modes

`--mode passive` — analyze HTML only (zero "noisy" requests)
`--mode mixed` _(default)_ — passive + targeted readme.txt / style.css probes
`--mode aggressive` — full plugin/theme wordlist enumeration (~1–10 min, may trigger WAFs)

## Configuration

Defaults can be overridden via `~/.config/wp-shield/config.yaml`:

```yaml
http:
  timeout: 15
  max_concurrency: 10
  user_agent: "wp-shield/0.1 (+https://github.com/pepperonas/wp-shield)"
  respect_robots_txt: true
  rate_limit_per_second: 5

scan:
  default_mode: mixed
  enumerate_users: true
  follow_redirects: true
```

## Legal & Ethics

`wp-shield` is intended **exclusively for authorized security testing**. Running this tool against sites you do not own or have explicit written permission to test may be illegal in your jurisdiction (StGB §202a/b in Germany, Computer Fraud and Abuse Act in the US, UK Computer Misuse Act, etc.).

The author is not responsible for misuse. By using this software you agree that:

1. You will only scan systems you own or are explicitly authorized to test
2. You accept full responsibility for any consequences of running scans
3. You will respect rate-limits, `robots.txt`, and target system stability

The brute-force module (planned for v0.4) is **deliberately gated** behind a local `~/.config/wp-shield/owned-domains.txt` allow-list to prevent accidental misuse.

## Architecture

- **Stack**: Python 3.11+, `httpx` (async), `BeautifulSoup` + `lxml`, `typer` + `rich` (CLI), `pydantic` (models), `sqlite3` (vuln cache), `jinja2` (reports/UI)
- **Vuln data sources**:
  - **Default**: [WPVulnerability.net](https://www.wpvulnerability.net/) — free, no API key, per-component lookup. We pre-warm the cache with the top-N plugin/theme slugs from a built-in wordlist.
  - **Optional**: [Wordfence Intelligence v3](https://www.wordfence.com/products/wordfence-intelligence/) — requires a free Bearer token since the 2025 v3 migration (their v1/v2 endpoints now return HTTP 410 Gone).

See `docs/ARCHITECTURE.md` (planned).

## License

GPL-3.0-or-later — same license as the original WPScan and WPVulnerability projects.

## Acknowledgements

Inspired by:
- [WPScan](https://github.com/wpscanteam/wpscan) (Ruby, GPL-3.0) — the reference implementation
- [WPVulnerability](https://www.wpvulnerability.com/) — open vulnerability database
- [Wordfence](https://www.wordfence.com/) — for the free, commercial-use intelligence feed
