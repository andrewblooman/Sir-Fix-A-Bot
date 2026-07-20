"""Run records in Firestore, used to stop the same finding being worked twice.

Wiz re-fires an open finding on every rescan, so without this a weekly scan would reopen the same
pull request every cycle. The record is keyed on the finding's stable identity (service, CVE,
package, installed version) rather than the Wiz finding id, which changes between scans.

This is the first line of defence; the worker also checks GitHub for an open pull request on the
branch before doing any work, in case a record has been deleted or has aged out.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.models import Finding, FixOutcome, RunStatus

logger = logging.getLogger(__name__)

#: A run stuck in `running` for longer than this is presumed dead (the worker was evicted, or
#: Cloud Tasks gave up) and may be retried.
_STALE_RUN = timedelta(minutes=45)
#: How long a terminal outcome suppresses re-processing of the same finding.
_SUPPRESS_FOR = {
    RunStatus.PR_OPEN: timedelta(days=30),
    RunStatus.BLOCKED: timedelta(days=14),
    RunStatus.SKIPPED: timedelta(days=7),
    # A hard failure is worth retrying sooner; it is often transient.
    RunStatus.FAILED: timedelta(hours=6),
}


class RunStore:
    """Firestore-backed record of what has been attempted for each finding."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: Any = None

    def _collection(self) -> Any:
        if self._client is None:
            from google.cloud import firestore

            self._client = firestore.Client(
                project=self._settings.gcp_project, database=self._settings.firestore_database
            )
        return self._client.collection(self._settings.firestore_collection)

    def should_process(self, finding: Finding) -> tuple[bool, str]:
        """Return whether to enqueue this finding, and why not when the answer is no."""
        snapshot = self._collection().document(finding.dedupe_key).get()
        if not snapshot.exists:
            return True, ""

        record = snapshot.to_dict() or {}
        status = _status_of(record)
        updated = _timestamp_of(record.get("updated_at"))
        age = datetime.now(UTC) - updated if updated else None

        if status in (RunStatus.QUEUED, RunStatus.RUNNING):
            if age is not None and age > _STALE_RUN:
                logger.warning(
                    "Run %s has been %s for %s; treating it as dead and retrying",
                    finding.dedupe_key,
                    status.value,
                    age,
                )
                return True, ""
            return False, f"a run is already {status.value}"

        window = _SUPPRESS_FOR.get(status)
        if window and age is not None and age < window:
            return False, f"last run finished as {status.value} {_humanise(age)} ago"

        return True, ""

    def mark(self, finding: Finding, status: RunStatus, **fields: Any) -> None:
        """Upsert the run record."""
        payload: dict[str, Any] = {
            "dedupe_key": finding.dedupe_key,
            "status": status.value,
            "service_name": finding.service_name,
            "cve_id": finding.cve_id,
            "package_name": finding.package_name,
            "severity": finding.severity.value,
            "wiz_finding_id": finding.id,
            "updated_at": datetime.now(UTC),
            **fields,
        }
        self._collection().document(finding.dedupe_key).set(payload, merge=True)

    def record_outcome(self, outcome: FixOutcome) -> None:
        self.mark(
            outcome.finding,
            outcome.status,
            pr_url=str(outcome.pr_url) if outcome.pr_url else None,
            issue_url=str(outcome.issue_url) if outcome.issue_url else None,
            branch=outcome.branch,
            blocked_reason=outcome.blocked_reason,
            repo=outcome.service.repo_full_name if outcome.service else None,
            violations=[v.rule for v in outcome.violations],
            finished_at=outcome.finished_at,
        )


def _status_of(record: dict[str, Any]) -> RunStatus:
    try:
        return RunStatus(record.get("status", ""))
    except ValueError:
        return RunStatus.FAILED


def _timestamp_of(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return None


def _humanise(delta: timedelta) -> str:
    hours = delta.total_seconds() / 3600
    if hours < 1:
        return f"{int(delta.total_seconds() / 60)}m"
    if hours < 48:
        return f"{int(hours)}h"
    return f"{int(hours / 24)}d"
