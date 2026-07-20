"""Rendering for the pull request and issue bodies a run produces.

These are what a human actually reads, so they lead with what changed and why, and state plainly
what was and was not verified. An automated PR that overstates its confidence is worse than one that
is honest about its limits — the reviewer needs to know whether the tests ran.
"""

from __future__ import annotations

from sir_fix_a_bot.models import Finding, FixOutcome, ServiceRecord

_FOOTER = (
    "\n---\n"
    "Opened by [Sir-Fix-A-Bot](https://github.com/andrewblooman/Sir-Fix-A-Bot). "
    "The change was produced by an agent working under fixed constraints, checked against those "
    "constraints automatically, and verified by building the image and running the tests inside "
    "it. It still needs your review before merging.\n"
)


def pr_title(finding: Finding, service: ServiceRecord) -> str:
    subject = finding.cve_id or finding.name
    package = f" in {finding.package_name}" if finding.package_name else ""
    return f"fix({service.service_name}): remediate {subject}{package}"


def pr_body(outcome: FixOutcome) -> str:
    finding = outcome.finding
    sections: list[str] = []

    sections.append(outcome.summary.strip() or "No summary was produced.")

    sections.append(
        "## Finding\n\n"
        f"| | |\n| --- | --- |\n"
        f"| Vulnerability | {finding.cve_id or finding.name} |\n"
        f"| Severity | {finding.severity.value}"
        f"{f' (CVSS {finding.cvss_score})' if finding.cvss_score else ''} |\n"
        f"| Package | {finding.package_name or 'not reported'} |\n"
        f"| Installed | {finding.installed_version or 'not reported'} |\n"
        f"| Fixed in | {finding.fixed_version or 'no fixed version published'} |\n"
        f"| Service | {finding.service_name} |\n"
    )

    if outcome.changes:
        listed = "\n".join(f"- {c}" for c in outcome.changes)
        sections.append(f"## Changes\n\n{listed}")

    sections.append(_verification_section(outcome))

    if outcome.notes:
        listed = "\n".join(f"- {n}" for n in outcome.notes)
        sections.append(
            "## Notes from the agent\n\n"
            "Things it was unsure about, or unrelated problems it noticed but did not fix.\n\n"
            f"{listed}"
        )

    return "\n\n".join(sections) + _FOOTER


def _verification_section(outcome: FixOutcome) -> str:
    verification = outcome.verification
    lines = ["## Verification\n"]

    if verification is None:
        lines.append("- Not run (dry run).")
    else:
        lines.append(
            f"- Image build: {'passed' if verification.build_ok else 'failed'}"
            + (f" ([log]({verification.log_url}))" if verification.log_url else "")
        )
        if verification.tests_ok and outcome.tests_added:
            lines.append("- Tests: passed inside the built image, including tests added here.")
        elif verification.tests_ok:
            lines.append("- Tests: passed inside the built image.")
        else:
            lines.append("- Tests: **did not pass**.")

    if not outcome.tests_added and outcome.tests_rationale:
        lines.append(f"- No tests added — {outcome.tests_rationale}")

    lines.append(
        "- Constraints checked automatically: runtime version held, no `USER` directive "
        "introduced, OCI labels present with build-arg provenance, changes confined to the fix."
    )
    return "\n".join(lines)


def issue_title(finding: Finding, service: ServiceRecord) -> str:
    subject = finding.cve_id or finding.name
    return f"Cannot auto-remediate {subject} in {service.service_name}"


def issue_body(outcome: FixOutcome) -> str:
    """Body for a finding that could not be fixed within the house rules.

    The point of this issue is that the backlog stays visible: a finding nobody can act on is worse
    than one that is openly parked with a reason.
    """
    finding = outcome.finding
    sections: list[str] = []

    reason = outcome.blocked_reason
    if reason:
        sections.append(f"This finding could not be fixed automatically.\n\n**Reason:** {reason}")
    else:
        sections.append("This finding could not be fixed automatically.")

    sections.append(
        "## Finding\n\n"
        f"| | |\n| --- | --- |\n"
        f"| Vulnerability | {finding.cve_id or finding.name} |\n"
        f"| Severity | {finding.severity.value} |\n"
        f"| Package | {finding.package_name or 'not reported'} |\n"
        f"| Installed | {finding.installed_version or 'not reported'} |\n"
        f"| Fixed in | {finding.fixed_version or 'no fixed version published'} |\n"
        f"| Service | {finding.service_name} |\n"
    )

    if outcome.violations:
        listed = "\n".join(f"- {v.render()}" for v in outcome.violations)
        sections.append(
            "## Why the attempt was rejected\n\n"
            "The agent produced a change, but it breached the constraints it works under:\n\n"
            f"{listed}"
        )

    if outcome.verification and not outcome.verification.passed:
        excerpt = outcome.verification.failure_excerpt.strip()[:2000]
        sections.append(f"## Verification failure\n\n```\n{excerpt}\n```")

    if outcome.notes:
        listed = "\n".join(f"- {n}" for n in outcome.notes)
        sections.append(f"## Notes from the agent\n\n{listed}")

    sections.append(
        "## What a human needs to decide\n\n"
        "The most common cause is a fix that would require bumping the runtime's major or minor "
        "version, which this tool will not do on its own because it changes language semantics "
        "and library compatibility. If that upgrade is wanted, it should be planned deliberately "
        "rather than folded into a security patch."
    )

    return "\n\n".join(sections) + _FOOTER
