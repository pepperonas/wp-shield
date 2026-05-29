"""Domain models for wp-shield.

All scanner output is modelled here as Pydantic types so that JSON / SARIF /
HTML renderers can rely on a single source of truth.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def sarif_level(self) -> str:
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]

    @property
    def numeric(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class ScanMode(str, Enum):
    PASSIVE = "passive"
    MIXED = "mixed"
    AGGRESSIVE = "aggressive"


class ComponentType(str, Enum):
    CORE = "core"
    PLUGIN = "plugin"
    THEME = "theme"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Vulnerability(BaseModel):
    """A known CVE / security issue from the vuln DB."""

    model_config = ConfigDict(extra="ignore")

    uuid: str
    title: str
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    description: str | None = None
    published_at: datetime | None = None
    source: str = "wordfence"
    # The slug + version range that matched
    affected_slug: str | None = None
    affected_type: ComponentType | None = None
    from_version: str | None = None
    from_inclusive: bool | None = None
    to_version: str | None = None
    to_inclusive: bool | None = None


class Component(BaseModel):
    """A detected WordPress component (core, plugin, theme)."""

    type: ComponentType
    slug: str
    name: str | None = None
    version: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    detection_methods: list[str] = Field(default_factory=list)
    location: str | None = None  # e.g. URL where it was found
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class User(BaseModel):
    """An enumerated WordPress user account."""

    id: int | None = None
    login: str | None = None
    display_name: str | None = None
    slug: str | None = None
    detection_methods: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single observation produced by a check or detection module."""

    rule_id: str  # stable machine identifier, e.g. "xmlrpc.exposed"
    title: str
    severity: Severity
    description: str | None = None
    evidence: str | None = None
    location: str | None = None  # URL or path
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM
    tags: list[str] = Field(default_factory=list)


class TargetInfo(BaseModel):
    """Resolved info about the scan target."""

    raw_input: str
    url: str
    host: str
    ip: str | None = None
    reachable: bool = False
    final_url: str | None = None  # after redirects
    waf: str | None = None
    server_header: str | None = None
    powered_by: str | None = None


class ScanResult(BaseModel):
    """Aggregated scan output, used to render all report formats."""

    target: TargetInfo
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    mode: ScanMode = ScanMode.MIXED
    is_wordpress: bool = False
    wp_detection_signals: list[str] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    users: list[User] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    tool: dict[str, str] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def core(self) -> Component | None:
        for c in self.components:
            if c.type == ComponentType.CORE:
                return c
        return None

    @property
    def plugins(self) -> list[Component]:
        return [c for c in self.components if c.type == ComponentType.PLUGIN]

    @property
    def themes(self) -> list[Component]:
        return [c for c in self.components if c.type == ComponentType.THEME]

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(c.vulnerabilities) for c in self.components)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        for c in self.components:
            for v in c.vulnerabilities:
                counts[v.severity.value] += 1
        return counts

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent, exclude_none=True)


class TargetSpec(BaseModel):
    """A target as supplied by the user (CLI arg or web form)."""

    url: HttpUrl
    extra: dict[str, Any] = Field(default_factory=dict)
