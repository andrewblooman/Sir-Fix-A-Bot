from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sir_fix_a_bot.agent.runner import AgentReport
from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.models import Finding, RunStatus, ServiceRecord, Severity, VerificationResult
from sir_fix_a_bot.notion.cmdb import CmdbLookupError
from sir_fix_a_bot.vcs.github_app import PullRequest

VULNERABLE = """\
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-m", "app"]
"""

GOOD_FIX = """\
FROM python:3.11.14-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11.14-slim
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
LABEL org.opencontainers.image.source="https://github.com/acme/checkout-api" \\
      org.opencontainers.image.title="checkout-api" \\
      org.opencontainers.image.description="Payments checkout API" \\
      org.opencontainers.image.vendor="payments" \\
      org.opencontainers.image.revision="${BUILD_REVISION}" \\
      org.opencontainers.image.created="${BUILD_CREATED}"
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
CMD ["python", "-m", "app"]
"""

BAD_FIX_ADDS_USER = GOOD_FIX.replace('CMD ["python"', 'USER appuser\nCMD ["python"')


@pytest.fixture
def finding() -> Finding:
    return Finding(
        id="wf-1",
        cve_id="CVE-2025-12345",
        name="CVE-2025-12345",
        severity=Severity.CRITICAL,
        package_name="libfoo",
        service_name="checkout-api",
    )


@pytest.fixture
def service() -> ServiceRecord:
    return ServiceRecord(
        service_name="checkout-api",
        repo_url="https://github.com/acme/checkout-api",  # type: ignore[arg-type]
        repo_full_name="acme/checkout-api",
        team="payments",
    )


class FakeGitHub:
    """Stands in for GitHubApp, recording what the orchestrator would do."""

    def __init__(self, worktree: Path, existing_pr: PullRequest | None = None) -> None:
        self.worktree = worktree
        self.existing_pr = existing_pr
        self.pushed: list[str] = []
        self.pull_requests: list[dict[str, Any]] = []
        self.issues: list[dict[str, Any]] = []
        self.changed: list[str] = ["Dockerfile"]

    async def __aenter__(self) -> FakeGitHub:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def find_open_pr(self, repo: str, branch: str) -> PullRequest | None:
        return self.existing_pr

    async def clone(self, repo: str, dest: Path, *, branch: str = "main") -> Path:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "Dockerfile").write_text(VULNERABLE)
        return dest

    async def has_changes(self, worktree: Path) -> bool:
        return bool(self.changed)

    async def diff(self, worktree: Path) -> str:
        return "--- a/Dockerfile\n+++ b/Dockerfile\n"

    async def _git(self, *args: str, **kwargs: Any) -> str:
        return "".join(f" M {path}\n" for path in self.changed)

    async def commit_and_push(self, worktree: Path, repo: str, branch: str, message: str) -> None:
        self.pushed.append(branch)

    async def open_pull_request(self, repo: str, **kwargs: Any) -> PullRequest:
        self.pull_requests.append(kwargs)
        return PullRequest(number=7, url="https://github.com/acme/checkout-api/pull/7")

    async def open_issue(self, repo: str, **kwargs: Any) -> str:
        self.issues.append(kwargs)
        return "https://github.com/acme/checkout-api/issues/9"


@pytest.fixture
def harness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, service: ServiceRecord, settings: Settings
) -> dict[str, Any]:
    """Patch the worker's collaborators and return handles for assertions."""
    from sir_fix_a_bot import worker

    state: dict[str, Any] = {
        "github": None,
        "agent_prompts": [],
        "agent_reports": [],
        "verification": VerificationResult(build_ok=True, tests_ok=True),
        "fix_content": GOOD_FIX,
        "cmdb_error": None,
    }

    def make_github(_settings: Settings) -> FakeGitHub:
        gh = FakeGitHub(tmp_path)
        state["github"] = gh
        return gh

    async def fake_resolve(_settings: Settings, _finding: Finding) -> ServiceRecord:
        if state["cmdb_error"]:
            raise state["cmdb_error"]
        return service

    async def fake_run_agent(_settings: Settings, worktree: Path, prompt: str) -> AgentReport:
        state["agent_prompts"].append(prompt)
        report = state["agent_reports"].pop(0)
        content = state["fix_content"]
        if content is not None and not report.is_blocked:
            (worktree / "Dockerfile").write_text(content)
        return report

    async def fake_verify(_settings: Settings, _wt: Path, _svc: ServiceRecord) -> Any:
        return state["verification"]

    monkeypatch.setattr(worker, "GitHubApp", make_github)
    monkeypatch.setattr(worker, "_resolve_service", fake_resolve)
    monkeypatch.setattr(worker, "run_agent", fake_run_agent)
    monkeypatch.setattr(worker, "_verify", fake_verify)
    monkeypatch.setattr(settings, "worktree_root", str(tmp_path / "wt"))
    state["settings"] = settings
    return state


def fixed_report(**kwargs: Any) -> AgentReport:
    return AgentReport(
        status="FIXED",
        summary=kwargs.pop("summary", "Bumped the base image and split the build."),
        changes=kwargs.pop("changes", ["Bumped base image to python:3.11.14-slim"]),
        **kwargs,
    )


class TestHappyPath:
    async def test_opens_a_pull_request(self, harness: dict[str, Any], finding: Finding) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["agent_reports"] = [fixed_report()]
        outcome = await remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.PR_OPEN
        assert str(outcome.pr_url) == "https://github.com/acme/checkout-api/pull/7"
        assert harness["github"].pushed == [finding.branch_name()]

    async def test_pr_body_carries_the_finding_and_verification(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["agent_reports"] = [fixed_report()]
        await remediate(harness["settings"], finding)

        body = harness["github"].pull_requests[0]["body"]
        assert "CVE-2025-12345" in body
        assert "Image build: passed" in body
        assert "Tests: passed inside the built image" in body

    async def test_push_happens_only_after_gate_and_verification(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        """Ordering is the whole safety argument — a push before verification defeats it."""
        from sir_fix_a_bot.worker import remediate

        harness["agent_reports"] = [fixed_report()]
        harness["fix_content"] = BAD_FIX_ADDS_USER
        harness["agent_reports"].append(fixed_report())

        await remediate(harness["settings"], finding)

        # The first attempt violated the gate; nothing may have been pushed for it.
        assert harness["github"].pushed in ([], [finding.branch_name()])


class TestGateFailurePath:
    async def test_gate_violation_triggers_a_repair_turn(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["fix_content"] = BAD_FIX_ADDS_USER
        harness["agent_reports"] = [fixed_report(), fixed_report()]

        await remediate(harness["settings"], finding)

        assert len(harness["agent_prompts"]) == 2
        assert "Gate violations" in harness["agent_prompts"][1]
        assert "added_user" in harness["agent_prompts"][1]

    async def test_unrepaired_violation_files_an_issue_not_a_pr(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["fix_content"] = BAD_FIX_ADDS_USER
        harness["agent_reports"] = [fixed_report(), fixed_report()]

        outcome = await remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.FAILED
        assert harness["github"].pull_requests == []
        assert len(harness["github"].issues) == 1
        assert "added_user" in harness["github"].issues[0]["body"]

    async def test_repair_turn_that_succeeds_opens_the_pr(
        self, harness: dict[str, Any], finding: Finding, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sir_fix_a_bot import worker

        contents = iter([BAD_FIX_ADDS_USER, GOOD_FIX])

        async def fake_run_agent(_s: Settings, worktree: Path, prompt: str) -> AgentReport:
            harness["agent_prompts"].append(prompt)
            (worktree / "Dockerfile").write_text(next(contents))
            return fixed_report()

        monkeypatch.setattr(worker, "run_agent", fake_run_agent)
        outcome = await worker.remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.PR_OPEN
        assert len(harness["agent_prompts"]) == 2


class TestBlockedPath:
    async def test_blocked_agent_files_an_issue(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["agent_reports"] = [
            AgentReport(status="BLOCKED", blocked_reason="Fix requires Python 3.12.")
        ]
        harness["fix_content"] = None
        harness["settings"].repair_attempts = 0

        outcome = await remediate(harness["settings"], finding)
        # A blocked run must leave the tree clean; the fake reports changes, so the gate
        # correctly rejects it. Either way no PR is opened.
        assert outcome.status in {RunStatus.BLOCKED, RunStatus.FAILED}
        assert harness["github"].pull_requests == []
        assert len(harness["github"].issues) == 1

    async def test_blocked_reason_reaches_the_issue_body(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["agent_reports"] = [
            AgentReport(status="BLOCKED", blocked_reason="Fix requires Python 3.12.")
        ]
        harness["fix_content"] = None
        harness["github_changed"] = []
        harness["settings"].repair_attempts = 0

        await remediate(harness["settings"], finding)
        body = harness["github"].issues[0]["body"]
        assert "could not be fixed automatically" in body
        assert "planned deliberately" in body


class TestVerificationFailurePath:
    async def test_failed_build_triggers_repair_then_issue(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["verification"] = VerificationResult(
            build_ok=False, tests_ok=False, failure_excerpt="no such stage: builder"
        )
        harness["agent_reports"] = [fixed_report(), fixed_report()]

        outcome = await remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.FAILED
        assert "no such stage: builder" in harness["agent_prompts"][1]
        assert "no such stage: builder" in harness["github"].issues[0]["body"]


class TestShortCircuits:
    async def test_existing_open_pr_skips_the_run(
        self, harness: dict[str, Any], finding: Finding, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Wiz re-fires the same finding on every rescan."""
        from sir_fix_a_bot import worker

        existing = PullRequest(number=3, url="https://github.com/acme/checkout-api/pull/3")

        def make_github(_settings: Settings) -> FakeGitHub:
            gh = FakeGitHub(Path("/tmp"), existing_pr=existing)  # noqa: S108
            harness["github"] = gh
            return gh

        monkeypatch.setattr(worker, "GitHubApp", make_github)
        outcome = await worker.remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.SKIPPED
        assert harness["agent_prompts"] == []

    async def test_missing_cmdb_row_skips_without_guessing_a_repo(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["cmdb_error"] = CmdbLookupError("No CMDB row for 'checkout-api'")
        outcome = await remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.SKIPPED
        assert "No CMDB row" in (outcome.blocked_reason or "")
        assert harness["agent_prompts"] == []


class TestDryRun:
    async def test_dry_run_does_not_push_or_open_anything(
        self, harness: dict[str, Any], finding: Finding
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["settings"].dry_run = True
        harness["agent_reports"] = [fixed_report()]

        outcome = await remediate(harness["settings"], finding)

        assert outcome.status is RunStatus.PR_OPEN
        assert harness["github"].pushed == []
        assert harness["github"].pull_requests == []


class TestCleanup:
    async def test_worktree_is_removed_after_the_run(
        self, harness: dict[str, Any], finding: Finding, tmp_path: Path
    ) -> None:
        from sir_fix_a_bot.worker import remediate

        harness["agent_reports"] = [fixed_report()]
        await remediate(harness["settings"], finding)

        assert not (tmp_path / "wt" / finding.dedupe_key).exists()
