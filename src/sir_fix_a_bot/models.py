"""Shared vocabulary for the remediation pipeline.

A run carries one `Finding` from Wiz through a `ServiceRecord` lookup in the Notion CMDB to a
`FixOutcome`. Every stage boundary in `worker.py` is typed in terms of these.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl


class Severity(StrEnum):
    """Wiz severity levels, ordered low to critical."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = [
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order.index(self)

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


class RunStatus(StrEnum):
    """Lifecycle of a single remediation run, persisted in Firestore."""

    QUEUED = "queued"
    RUNNING = "running"
    PR_OPEN = "pr_open"
    #: The finding is real but unfixable under the house rules (e.g. needs a minor version bump).
    BLOCKED = "blocked"
    FAILED = "failed"
    #: Dropped before any work — duplicate, below severity threshold, or no CMDB entry.
    SKIPPED = "skipped"

    @property
    def is_terminal(self) -> bool:
        return self in {
            RunStatus.PR_OPEN,
            RunStatus.BLOCKED,
            RunStatus.FAILED,
            RunStatus.SKIPPED,
        }


class Finding(BaseModel):
    """A single vulnerability finding, normalised from Wiz.

    `id` is Wiz's own finding id and is *not* stable across rescans — use `dedupe_key` for identity.
    """

    id: str
    cve_id: str | None = None
    name: str
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None

    #: Vulnerable package as Wiz sees it, e.g. "libssl3" / "requests".
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    #: The Cloud Run service this finding was observed on. The join key into the Notion CMDB.
    service_name: str
    cloud_provider: str = "GCP"
    project_id: str | None = None
    region: str | None = None

    #: Container image the finding was detected in, when Wiz reports it.
    image_ref: str | None = None

    detected_at: datetime | None = None
    wiz_url: HttpUrl | None = None

    @property
    def dedupe_key(self) -> str:
        """Stable identity for this vulnerability, independent of Wiz's per-scan finding id.

        Wiz re-fires the same finding on every rescan with a fresh `id`, so deduping on `id` would
        open a duplicate PR each scan cycle.
        """
        parts = [
            self.service_name,
            self.cve_id or self.name,
            self.package_name or "",
            self.installed_version or "",
        ]
        return hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:32]

    @property
    def short_ref(self) -> str:
        """Human-facing slug used in branch names, e.g. `cve-2025-1234`."""
        raw = (self.cve_id or self.name).lower()
        slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
        return slug[:48] or "unknown"

    def branch_name(self) -> str:
        return f"fix/wiz-{self.short_ref}-{self.dedupe_key[:8]}"


class ServiceRecord(BaseModel):
    """A Cloud Run service's row in the Notion CMDB.

    `owner`/`team` feed the OCI image labels, which is why the agent keeps read access to the
    Notion MCP server rather than us passing only the repo URL through.
    """

    service_name: str
    repo_url: HttpUrl
    #: "owner/name", derived from repo_url.
    repo_full_name: str
    default_branch: str = "main"
    owner: str | None = None
    team: str | None = None
    #: Path to the Dockerfile within the repo, when the CMDB records a non-default location.
    dockerfile_path: str = "Dockerfile"
    notion_page_url: HttpUrl | None = None


class GateViolation(BaseModel):
    """One breached post-condition, fed back to the agent for its single repair turn."""

    #: Stable identifier, e.g. "added_user", "runtime_version_changed".
    rule: str
    message: str
    file: str | None = None
    line: int | None = None

    def render(self) -> str:
        where = f" ({self.file}:{self.line})" if self.file and self.line else ""
        return f"[{self.rule}]{where} {self.message}"


class VerificationResult(BaseModel):
    """Outcome of the Cloud Build image build + in-image test run."""

    build_ok: bool
    tests_ok: bool
    build_id: str | None = None
    log_url: HttpUrl | None = None
    #: Trimmed failure output, for the repair turn and the issue body.
    failure_excerpt: str = ""

    @property
    def passed(self) -> bool:
        return self.build_ok and self.tests_ok


class FixOutcome(BaseModel):
    """Terminal result of a run. Persisted and used to build the PR or issue body."""

    finding: Finding
    service: ServiceRecord | None = None
    status: RunStatus
    branch: str | None = None
    pr_url: HttpUrl | None = None
    issue_url: HttpUrl | None = None
    diff: str = ""
    #: The agent's own explanation of what it changed and why.
    summary: str = ""
    #: Bullet list of the individual changes made, for the PR body.
    changes: list[str] = Field(default_factory=list)
    #: Things the agent was unsure about, or unrelated problems it noticed.
    notes: list[str] = Field(default_factory=list)
    tests_added: bool = False
    tests_rationale: str = ""
    #: Set when the agent reported it could not fix within the house rules.
    blocked_reason: str | None = None
    violations: list[GateViolation] = Field(default_factory=list)
    verification: VerificationResult | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
