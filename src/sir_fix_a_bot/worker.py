"""The remediation pipeline: one Wiz finding in, one pull request or issue out.

Stage order matters. The repository is resolved before anything is cloned, the gate runs before
anything is built, and the push happens only after both the gate and the verification build are
green. The agent never holds credentials at any point — pushing is done here.
"""

from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path

from sir_fix_a_bot.agent.gate import GateContext, evaluate
from sir_fix_a_bot.agent.runner import (
    AgentReport,
    build_fix_prompt,
    build_repair_prompt,
    run_agent,
)
from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.models import Finding, FixOutcome, RunStatus, ServiceRecord, VerificationResult
from sir_fix_a_bot.notion.cmdb import CmdbLookupError, NotionCmdb
from sir_fix_a_bot.report import issue_body, issue_title, pr_body, pr_title
from sir_fix_a_bot.vcs.github_app import GitHubApp
from sir_fix_a_bot.verify.cloudbuild import VerificationError, verify

logger = logging.getLogger(__name__)


async def remediate(settings: Settings, finding: Finding) -> FixOutcome:
    """Run the full pipeline for one finding."""
    outcome = FixOutcome(finding=finding, status=RunStatus.RUNNING, started_at=datetime.now(UTC))
    worktree = Path(settings.worktree_root) / finding.dedupe_key

    async with GitHubApp(settings) as github:
        try:
            service = await _resolve_service(settings, finding)
            outcome.service = service

            if existing := await github.find_open_pr(service.repo_full_name, finding.branch_name()):
                logger.info("PR already open for %s: %s", finding.dedupe_key, existing.url)
                outcome.status = RunStatus.SKIPPED
                outcome.pr_url = existing.url  # type: ignore[assignment]
                return _finish(outcome)

            await github.clone(service.repo_full_name, worktree, branch=service.default_branch)
            before_dockerfile = _read_dockerfile(worktree, service)

            report, outcome = await _fix_and_verify(
                settings, github, finding, service, worktree, before_dockerfile, outcome
            )

            if outcome.status is not RunStatus.RUNNING:
                # Blocked or failed during the fix loop; file an issue rather than a PR.
                return await _file_issue(github, service, outcome)

            return await _open_pull_request(settings, github, service, worktree, outcome)

        except CmdbLookupError as exc:
            # Without a repository there is nothing to open a PR against, and nowhere to file an
            # issue either — this has to surface through the run record.
            logger.error("CMDB lookup failed for %s: %s", finding.service_name, exc)
            outcome.status = RunStatus.SKIPPED
            outcome.blocked_reason = str(exc)
            return _finish(outcome)

        except Exception as exc:  # noqa: BLE001 - the run record must capture any failure
            logger.exception("Remediation failed for %s", finding.dedupe_key)
            outcome.status = RunStatus.FAILED
            outcome.blocked_reason = f"{type(exc).__name__}: {exc}"
            return _finish(outcome)

        finally:
            shutil.rmtree(worktree, ignore_errors=True)


async def _resolve_service(settings: Settings, finding: Finding) -> ServiceRecord:
    async with NotionCmdb(settings) as cmdb:
        return await cmdb.resolve(finding.service_name)


def _read_dockerfile(worktree: Path, service: ServiceRecord) -> str | None:
    path = worktree / service.dockerfile_path
    if not path.is_file():
        logger.warning("No Dockerfile at %s", path)
        return None
    return path.read_text(encoding="utf-8", errors="replace")


async def _fix_and_verify(
    settings: Settings,
    github: GitHubApp,
    finding: Finding,
    service: ServiceRecord,
    worktree: Path,
    before_dockerfile: str | None,
    outcome: FixOutcome,
) -> tuple[AgentReport, FixOutcome]:
    """Run the agent, gate it, verify it, and grant one repair turn on failure."""
    prompt = build_fix_prompt(finding, service, worktree)
    report = await run_agent(settings, worktree, prompt)

    for attempt in range(settings.repair_attempts + 1):
        _absorb(outcome, report)
        has_changes = await github.has_changes(worktree)

        violations = evaluate(
            GateContext(
                before_dockerfile=before_dockerfile,
                after_dockerfile=_read_dockerfile(worktree, service),
                changed_files=await _changed_files(github, worktree),
                agent_blocked=report.is_blocked,
                has_changes=has_changes,
            )
        )
        outcome.violations = violations

        if report.is_blocked and not violations:
            outcome.status = RunStatus.BLOCKED
            outcome.blocked_reason = report.blocked_reason or "Agent reported the fix as blocked."
            return report, outcome

        verification: VerificationResult | None = None
        if not violations:
            verification = await _verify(settings, worktree, service)
            outcome.verification = verification

        if not violations and (verification is None or verification.passed):
            outcome.diff = await github.diff(worktree)
            return report, outcome

        if attempt >= settings.repair_attempts:
            break

        logger.info(
            "Repair turn %s for %s: %s violations, verification=%s",
            attempt + 1,
            finding.dedupe_key,
            len(violations),
            "n/a" if verification is None else verification.passed,
        )
        report = await run_agent(
            settings, worktree, build_repair_prompt(service, violations, verification)
        )

    outcome.status = RunStatus.BLOCKED if report.is_blocked else RunStatus.FAILED
    outcome.blocked_reason = report.blocked_reason or _failure_reason(outcome)
    return report, outcome


async def _verify(
    settings: Settings, worktree: Path, service: ServiceRecord
) -> VerificationResult | None:
    if settings.dry_run:
        logger.info("Dry run: skipping the verification build")
        return None
    try:
        return await verify(settings, worktree, service.dockerfile_path)
    except VerificationError as exc:
        logger.error("Verification could not run: %s", exc)
        return VerificationResult(build_ok=False, tests_ok=False, failure_excerpt=str(exc))


async def _changed_files(github: GitHubApp, worktree: Path) -> list[str]:
    output = await github._git("status", "--porcelain", cwd=worktree)
    files: list[str] = []
    for line in output.splitlines():
        path = line[3:].strip() if len(line) > 3 else ""
        # Renames are reported as "old -> new"; the destination is what matters for scope.
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path:
            files.append(path.strip('"'))
    return files


def _failure_reason(outcome: FixOutcome) -> str:
    if outcome.violations:
        return "The change breached the constraints: " + "; ".join(
            v.render() for v in outcome.violations
        )
    if outcome.verification and not outcome.verification.passed:
        what = "The image did not build." if not outcome.verification.build_ok else "Tests failed."
        return f"{what} See the verification output."
    return "The fix could not be completed."


async def _open_pull_request(
    settings: Settings,
    github: GitHubApp,
    service: ServiceRecord,
    worktree: Path,
    outcome: FixOutcome,
) -> FixOutcome:
    finding = outcome.finding
    branch = finding.branch_name()
    outcome.branch = branch

    if settings.dry_run:
        logger.info("Dry run: not pushing %s", branch)
        outcome.status = RunStatus.PR_OPEN
        return _finish(outcome)

    title = pr_title(finding, service)
    await github.commit_and_push(worktree, service.repo_full_name, branch, _commit_message(outcome))
    pr = await github.open_pull_request(
        service.repo_full_name,
        branch=branch,
        base=service.default_branch,
        title=title,
        body=pr_body(outcome),
        labels=[settings.github_label],
    )
    outcome.pr_url = pr.url  # type: ignore[assignment]
    outcome.status = RunStatus.PR_OPEN
    return _finish(outcome)


def _commit_message(outcome: FixOutcome) -> str:
    finding = outcome.finding
    service = outcome.service
    name = service.service_name if service else "service"
    subject = f"fix({name}): remediate {finding.cve_id or finding.name}"
    body = outcome.summary.strip() or "Automated container vulnerability remediation."
    changes = "\n".join(f"- {c}" for c in outcome.changes)
    trailer = f"\nWiz-Finding: {finding.id}\nWiz-Dedupe-Key: {finding.dedupe_key}"
    return f"{subject}\n\n{body}\n\n{changes}\n{trailer}".strip()


async def _file_issue(github: GitHubApp, service: ServiceRecord, outcome: FixOutcome) -> FixOutcome:
    """Record an unfixable finding as an issue so the backlog stays visible."""
    try:
        url = await github.open_issue(
            service.repo_full_name,
            title=issue_title(outcome.finding, service),
            body=issue_body(outcome),
        )
        outcome.issue_url = url  # type: ignore[assignment]
        logger.info("Filed issue %s", url)
    except Exception:  # noqa: BLE001 - a failed issue must not mask the original outcome
        logger.exception("Could not file an issue for %s", outcome.finding.dedupe_key)
    return _finish(outcome)


def _absorb(outcome: FixOutcome, report: AgentReport) -> None:
    """Copy the agent's structured self-report onto the run outcome."""
    outcome.summary = report.summary
    outcome.changes = report.changes
    outcome.notes = report.notes
    outcome.tests_added = report.tests_added
    outcome.tests_rationale = report.tests_rationale


def _finish(outcome: FixOutcome) -> FixOutcome:
    outcome.finished_at = datetime.now(UTC)
    return outcome
