# Contributing to wp-shield

Thanks for considering a contribution! `wp-shield` is built to be hackable —
detection modules, checks and reporters live in small files with consistent
interfaces, so dropping in a new one is straightforward.

## Quick setup

```bash
git clone https://github.com/pepperonas/wp-shield.git
cd wp-shield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Where things live

- `src/wp_shield/core/`   — HTTP client, target probing, WAF detection, fingerprint, report rendering
- `src/wp_shield/detect/` — passive / mixed / aggressive component enumerators (one module per artefact: version, plugins, themes, users, config_files)
- `src/wp_shield/checks/` — misconfiguration probes; each exposes `async def run(http, base_url) -> list[Finding]`
- `src/wp_shield/vulndb/` — local SQLite vuln cache + Wordfence / WPVulnerability syncs + version-range matching
- `src/wp_shield/data/`   — plugin/theme wordlists (drop-in user overrides in `~/.config/wp-shield/`)
- `tests/unit/`           — fast unit tests using `respx` to mock HTTP

## Writing a new check

1. Create `src/wp_shield/checks/<name>.py` with a single `async def run(http, base_url) -> list[Finding]`
2. Use a stable `rule_id` like `wp.<area>.<thing>` (e.g. `wp.xmlrpc.exposed`)
3. Pick the smallest `Severity` that truthfully describes the impact — defaults err *low*
4. Add `tests/unit/test_checks_<name>.py` that mocks responses with `@respx.mock`
5. Wire the new module into `src/wp_shield/scan.py`

## Code style

- `ruff check src tests` must pass
- Functions get type hints; no `Any` unless we have to
- Comments only where the *why* would surprise a future reader

## Reporting security issues

Please **do not** open public issues for security problems. Email
`martin.pfeffer@celox.io` with a description and we'll coordinate disclosure.

## License

By contributing you agree your contributions will be licensed under GPL-3.0-or-later.
