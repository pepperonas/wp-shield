# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-29

### Added
- Initial release: CLI scanner with WordPress fingerprinting
- Core version detection (generator meta, readme.html, RSS, /wp-includes/css/buttons.css hash)
- Plugin enumeration (passive / mixed / aggressive modes)
- Theme enumeration via style.css header parsing
- User enumeration via REST API, ?author=N, oEmbed, author-sitemap
- Misconfiguration checks: xmlrpc, wp-cron, registration, debug.log, directory listing, readme exposure, security headers
- Config-backup file detection (wp-config.php.{bak,old,swp,~,save,...}, .sql, .tar.gz, .zip, .git, .env)
- Local CVE database (WPVulnerability.net feed → SQLite; Wordfence Intelligence v3 supported opt-in via Bearer token)
- Version-range vulnerability matching
- Reports: CLI (Rich), JSON, HTML, SARIF 2.1.0
- Polite defaults: robots.txt respect, rate-limiting, identifying user-agent
