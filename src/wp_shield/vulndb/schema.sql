-- wp-shield vulnerability database schema.

CREATE TABLE IF NOT EXISTS vulnerability (
    uuid           TEXT PRIMARY KEY,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    cvss_score     REAL,
    cvss_vector    TEXT,
    cve_ids_json   TEXT,                   -- JSON array of CVE strings
    cwe_ids_json   TEXT,                   -- JSON array
    description    TEXT,
    published_at   TEXT,                   -- ISO8601
    updated_at     TEXT,
    source         TEXT NOT NULL DEFAULT 'wordfence',
    references_json TEXT,                  -- JSON array of {url, type}
    raw_json       TEXT                    -- entire upstream record for debugging
);

CREATE TABLE IF NOT EXISTS affected_software (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_uuid      TEXT NOT NULL REFERENCES vulnerability(uuid) ON DELETE CASCADE,
    slug           TEXT NOT NULL,           -- plugin/theme slug or "wordpress"
    type           TEXT NOT NULL,           -- 'plugin' | 'theme' | 'core'
    from_version   TEXT,                    -- NULL == any version up to "to"
    from_inclusive INTEGER NOT NULL DEFAULT 0,
    to_version     TEXT,                    -- NULL == unbounded
    to_inclusive   INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_affected_slug_type
    ON affected_software(slug, type);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url    TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    mode          TEXT NOT NULL,
    is_wordpress  INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    vuln_count    INTEGER NOT NULL DEFAULT 0,
    report_json   TEXT
);
