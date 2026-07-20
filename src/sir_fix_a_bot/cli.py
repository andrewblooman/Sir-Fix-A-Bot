"""Command line entry point, primarily for the dry-run development loop.

`fix --finding-id <id> --dry-run` runs the whole pipeline against a real Wiz finding and prints the
diff, the verification result and the pull request body it would open, without pushing anything.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from sir_fix_a_bot.config import Settings, get_settings
from sir_fix_a_bot.models import Finding, FixOutcome, RunStatus, Severity
from sir_fix_a_bot.report import pr_body, pr_title
from sir_fix_a_bot.wiz.client import WizClient
from sir_fix_a_bot.worker import remediate

logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sir-fix-a-bot", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    fix = sub.add_parser("fix", help="remediate a single Wiz finding")
    fix.add_argument("--finding-id", required=True, help="Wiz vulnerability finding id")
    fix.add_argument(
        "--dry-run",
        action="store_true",
        help="run everything but skip the verification build and the push",
    )

    listing = sub.add_parser("findings", help="list open findings for a Cloud Run service")
    listing.add_argument("--service", required=True)
    listing.add_argument("--min-severity", default="HIGH", choices=[s.value for s in Severity])

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    match args.command:
        case "fix":
            return asyncio.run(_fix(args.finding_id, dry_run=args.dry_run))
        case "findings":
            return asyncio.run(_findings(args.service, args.min_severity))
        case _:
            parser.error(f"unknown command {args.command}")
            return 2


async def _fix(finding_id: str, *, dry_run: bool) -> int:
    settings = get_settings().model_copy(update={"dry_run": dry_run})

    finding = await _load_finding(settings, finding_id)
    if finding is None:
        print(f"No Wiz finding with id {finding_id}", file=sys.stderr)
        return 1

    outcome = await remediate(settings, finding)
    _print_outcome(outcome, dry_run=dry_run)
    return 0 if outcome.status in {RunStatus.PR_OPEN, RunStatus.BLOCKED} else 1


async def _load_finding(settings: Settings, finding_id: str) -> Finding | None:
    async with WizClient(settings) as wiz:
        return await wiz.get_finding(finding_id)


async def _findings(service: str, min_severity: str) -> int:
    settings = get_settings()
    threshold = Severity(min_severity)

    async with WizClient(settings) as wiz:
        findings = await wiz.open_findings_for_service(service)

    selected = [f for f in findings if f.severity >= threshold]
    if not selected:
        print(f"No open findings at or above {threshold.value} for {service}")
        return 0

    for finding in sorted(selected, key=lambda f: f.severity.rank, reverse=True):
        print(
            f"{finding.severity.value:<13} {finding.id:<24} "
            f"{finding.cve_id or finding.name:<20} {finding.package_name or ''}"
        )
    return 0


def _print_outcome(outcome: FixOutcome, *, dry_run: bool) -> None:
    rule = "=" * 78
    print(f"\n{rule}\nStatus: {outcome.status.value}")
    if outcome.service:
        print(f"Repo:   {outcome.service.repo_full_name}")
    if outcome.branch:
        print(f"Branch: {outcome.branch}")

    if outcome.violations:
        print("\nGate violations:")
        for violation in outcome.violations:
            print(f"  - {violation.render()}")

    if outcome.verification:
        verification = outcome.verification
        print(
            f"\nVerification: build={'ok' if verification.build_ok else 'FAILED'} "
            f"tests={'ok' if verification.tests_ok else 'FAILED'}"
        )
        if verification.failure_excerpt:
            print(f"  {verification.failure_excerpt[:800]}")

    if outcome.blocked_reason:
        print(f"\nBlocked: {outcome.blocked_reason}")

    if outcome.diff:
        print(f"\n{rule}\nDiff\n{rule}\n{outcome.diff}")

    if dry_run and outcome.status is RunStatus.PR_OPEN and outcome.service:
        print(f"\n{rule}\nPull request that would be opened\n{rule}")
        print(f"Title: {pr_title(outcome.finding, outcome.service)}\n")
        print(pr_body(outcome))

    if outcome.pr_url:
        print(f"\nPR:    {outcome.pr_url}")
    if outcome.issue_url:
        print(f"Issue: {outcome.issue_url}")


if __name__ == "__main__":
    raise SystemExit(main())
