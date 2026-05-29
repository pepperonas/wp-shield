"""SQLite-backed vulnerability store. Thin wrapper around stdlib ``sqlite3``."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from ..settings import db_path, ensure_dirs


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class VulnStore:
    """All persistence operations (vuln DB + scan history) live here."""

    def __init__(self, path: Path | None = None) -> None:
        ensure_dirs()
        self.path = path or db_path()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA journal_mode = WAL")
        return con

    def _init_schema(self) -> None:
        schema = files("wp_shield.vulndb").joinpath("schema.sql").read_text(encoding="utf-8")
        with self._connect() as con:
            con.executescript(schema)

    # ------------------------------------------------------------------ meta

    def get_meta(self, key: str) -> str | None:
        with self._connect() as con:
            row = con.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as con:
            con.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def last_sync(self) -> str | None:
        return self.get_meta("last_sync_at")

    # ------------------------------------------------------------- vuln ops

    def stats(self) -> dict[str, Any]:
        with self._connect() as con:
            total = con.execute("SELECT COUNT(*) c FROM vulnerability").fetchone()["c"]
            by_type = {
                row["type"]: row["c"]
                for row in con.execute(
                    "SELECT type, COUNT(DISTINCT vuln_uuid) c FROM affected_software GROUP BY type"
                ).fetchall()
            }
        return {
            "total_vulnerabilities": total,
            "by_component_type": by_type,
            "last_sync": self.last_sync(),
            "db_path": str(self.path),
        }

    def upsert_vulnerabilities(self, records: Iterable[dict[str, Any]]) -> int:
        """Upsert a batch of vulnerability records. Returns count written."""
        with self._connect() as con:
            cur = con.cursor()
            count = 0
            for rec in records:
                cur.execute(
                    "INSERT INTO vulnerability("
                    "uuid, title, severity, cvss_score, cvss_vector, cve_ids_json, "
                    "cwe_ids_json, description, published_at, updated_at, source, "
                    "references_json, raw_json) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(uuid) DO UPDATE SET "
                    "title=excluded.title, severity=excluded.severity, "
                    "cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector, "
                    "cve_ids_json=excluded.cve_ids_json, cwe_ids_json=excluded.cwe_ids_json, "
                    "description=excluded.description, published_at=excluded.published_at, "
                    "updated_at=excluded.updated_at, source=excluded.source, "
                    "references_json=excluded.references_json, raw_json=excluded.raw_json",
                    (
                        rec["uuid"],
                        rec["title"],
                        rec.get("severity", "medium"),
                        rec.get("cvss_score"),
                        rec.get("cvss_vector"),
                        json.dumps(rec.get("cve_ids") or []),
                        json.dumps(rec.get("cwe_ids") or []),
                        rec.get("description"),
                        rec.get("published_at"),
                        rec.get("updated_at"),
                        rec.get("source", "wordfence"),
                        json.dumps(rec.get("references") or []),
                        rec.get("raw_json"),
                    ),
                )
                # Replace affected_software rows for this vuln (idempotent sync)
                cur.execute("DELETE FROM affected_software WHERE vuln_uuid = ?", (rec["uuid"],))
                for aff in rec.get("affected", []):
                    cur.execute(
                        "INSERT INTO affected_software("
                        "vuln_uuid, slug, type, from_version, from_inclusive, "
                        "to_version, to_inclusive) VALUES(?,?,?,?,?,?,?)",
                        (
                            rec["uuid"],
                            aff["slug"],
                            aff["type"],
                            aff.get("from_version"),
                            int(bool(aff.get("from_inclusive"))),
                            aff.get("to_version"),
                            int(bool(aff.get("to_inclusive", True))),
                        ),
                    )
                count += 1
            con.commit()
            self.set_meta("last_sync_at", _now())
            return count

    def fetch_vuln(self, uuid: str) -> dict[str, Any] | None:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM vulnerability WHERE uuid = ?", (uuid,)
            ).fetchone()
            if row is None:
                return None
            return self._row_to_vuln(row)

    def candidate_vulns_for(self, slug: str, comp_type: str) -> list[dict[str, Any]]:
        """All vulns whose affected_software matches the (slug, type) tuple."""
        with self._connect() as con:
            rows = con.execute(
                "SELECT v.*, aff.from_version, aff.from_inclusive, "
                "       aff.to_version, aff.to_inclusive, aff.slug, aff.type "
                "FROM vulnerability v "
                "JOIN affected_software aff ON aff.vuln_uuid = v.uuid "
                "WHERE aff.slug = ? AND aff.type = ?",
                (slug.lower(), comp_type),
            ).fetchall()
        return [self._row_to_vuln(r, include_range=True) for r in rows]

    # -------------------------------------------------------------- history

    def record_scan(
        self,
        *,
        target_url: str,
        started_at: datetime,
        finished_at: datetime | None,
        mode: str,
        is_wordpress: bool,
        finding_count: int,
        vuln_count: int,
        report_json: str,
    ) -> int:
        with self._connect() as con:
            cur = con.execute(
                "INSERT INTO scan_history("
                "target_url, started_at, finished_at, mode, is_wordpress, "
                "finding_count, vuln_count, report_json) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    target_url,
                    started_at.isoformat(timespec="seconds"),
                    finished_at.isoformat(timespec="seconds") if finished_at else None,
                    mode,
                    int(is_wordpress),
                    finding_count,
                    vuln_count,
                    report_json,
                ),
            )
            con.commit()
            return int(cur.lastrowid or 0)

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT id, target_url, started_at, finished_at, mode, is_wordpress, "
                "finding_count, vuln_count FROM scan_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------- internal utils

    @staticmethod
    def _row_to_vuln(row: sqlite3.Row, include_range: bool = False) -> dict[str, Any]:
        data = dict(row)
        for json_key in ("cve_ids_json", "cwe_ids_json", "references_json"):
            if data.get(json_key):
                try:
                    data[json_key.replace("_json", "")] = json.loads(data[json_key])
                except json.JSONDecodeError:
                    data[json_key.replace("_json", "")] = []
            else:
                data[json_key.replace("_json", "")] = []
        if include_range:
            data["range"] = {
                "from_version": data.get("from_version"),
                "from_inclusive": bool(data.get("from_inclusive")),
                "to_version": data.get("to_version"),
                "to_inclusive": bool(data.get("to_inclusive", True)),
                "slug": data.get("slug"),
                "type": data.get("type"),
            }
        return data


@contextmanager
def open_store(path: Path | None = None) -> Iterator[VulnStore]:
    store = VulnStore(path=path)
    try:
        yield store
    finally:
        pass
