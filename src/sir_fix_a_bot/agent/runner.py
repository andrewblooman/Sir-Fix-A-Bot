"""Drives the Claude Agent SDK to produce a fix inside a cloned worktree.

The agent is treated as untrusted. Wiz finding text (CVE descriptions, package metadata) is
attacker-influenceable in principle, so the agent is given no credentials and no way to reach the
network with side effects: it can read and edit files in the worktree and run a narrow allowlist of
shell commands. Pushing and opening the pull request happen in the orchestrator, after the gate.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    TextBlock,
    ThinkingConfigAdaptive,
    ToolPermissionContext,
    query,
)

from sir_fix_a_bot.config import Settings, resolve_secret
from sir_fix_a_bot.models import Finding, GateViolation, ServiceRecord, VerificationResult

logger = logging.getLogger(__name__)

_PROMPT_DIR = Path(__file__).parent / "prompts"

#: File edits and searching. Deliberately excludes WebFetch/WebSearch — the agent has no reason to
#: reach the network, and the finding text it is reading is untrusted input.
_ALLOWED_TOOLS = ["Read", "Write", "Edit", "Grep", "Glob", "Bash", "TodoWrite"]

#: Shell programs the agent may invoke. Anything else is denied by `_check_tool_use`, so a prompt
#: injection cannot reach curl, gcloud, or a package publish.
_ALLOWED_COMMANDS = frozenset(
    {
        "cat",
        "ls",
        "head",
        "tail",
        "wc",
        "find",
        "grep",
        "rg",
        "sed",
        "awk",
        "sort",
        "uniq",
        "diff",
        "file",
        "stat",
        "basename",
        "dirname",
        "realpath",
        "echo",
        "true",
        "pwd",
        "test",
        "python",
        "python3",
        "pytest",
        "tox",
        "ruff",
        "mypy",
        "node",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "jq",
        "go",
        "cargo",
        "mvn",
        "gradle",
        "git",
    }
)

#: git subcommands that only read, or that stay local. `push`, `remote` and `config` are excluded so
#: the agent cannot reach GitHub or discover credentials.
_ALLOWED_GIT = frozenset(
    {
        "status",
        "diff",
        "log",
        "show",
        "ls-files",
        "add",
        "checkout",
        "restore",
        "rev-parse",
        "blame",
    }
)

_SHELL_OPERATORS = re.compile(r"(\|\||&&|[|;`]|\$\(|>\s*/|\bsudo\b)")
_JSON_BLOCK = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


@dataclass
class AgentReport:
    """The agent's structured self-report, parsed from the JSON block in its final message."""

    status: str = "FIXED"
    summary: str = ""
    changes: list[str] = field(default_factory=list)
    multistage: bool = False
    tests_added: bool = False
    tests_rationale: str = ""
    notes: list[str] = field(default_factory=list)
    blocked_reason: str | None = None
    #: Full final message, kept for diagnostics when parsing fails.
    raw: str = ""
    cost_usd: float | None = None
    turns: int = 0

    @property
    def is_blocked(self) -> bool:
        return self.status.upper() == "BLOCKED"


class AgentError(RuntimeError):
    """The agent could not be run to completion."""


def _load_prompt(name: str, **substitutions: str) -> str:
    """Render a prompt template.

    Uses explicit `{{NAME}}` replacement rather than `str.format`, because the templates contain
    Dockerfile and JSON braces that `format` would try to interpret.
    """
    text = (_PROMPT_DIR / name).read_text(encoding="utf-8")
    for key, value in substitutions.items():
        text = text.replace(f"{{{{{key}}}}}", value)
    if leftover := re.findall(r"\{\{([A-Z_]+)\}\}", text):
        raise AgentError(f"Prompt {name} has unfilled placeholders: {sorted(set(leftover))}")
    return text


def build_fix_prompt(finding: Finding, service: ServiceRecord, worktree: Path) -> str:
    vendor = service.team or service.owner or service.repo_full_name.split("/", 1)[0]
    cvss = f" (CVSS {finding.cvss_score})" if finding.cvss_score else ""
    description = (
        f"### Description\n\n{finding.description.strip()}\n" if finding.description else ""
    )

    return _load_prompt(
        "fix_vulnerability.md",
        SERVICE_NAME=service.service_name,
        REPO_FULL_NAME=service.repo_full_name,
        REPO_URL=str(service.repo_url),
        DOCKERFILE_PATH=service.dockerfile_path,
        VENDOR=vendor,
        FINDING_TITLE=finding.cve_id or finding.name,
        SEVERITY=finding.severity.value,
        CVSS=cvss,
        PACKAGE=finding.package_name or "not reported",
        INSTALLED_VERSION=finding.installed_version or "not reported",
        FIXED_VERSION=finding.fixed_version or "no fixed version published",
        DESCRIPTION=description,
        WORKTREE=str(worktree),
    )


def build_repair_prompt(
    service: ServiceRecord,
    violations: list[GateViolation],
    verification: VerificationResult | None,
) -> str:
    sections: list[str] = []

    if violations:
        listed = "\n".join(f"- {v.render()}" for v in violations)
        sections.append(
            "## Gate violations\n\n"
            "The automated gate rejected your diff for these reasons:\n\n" + listed
        )

    if verification and not verification.passed:
        what = "The image build failed." if not verification.build_ok else "The test suite failed."
        excerpt = verification.failure_excerpt.strip()[:4000] or "(no output captured)"
        sections.append(f"## Verification failure\n\n{what}\n\n```\n{excerpt}\n```")

    return _load_prompt(
        "repair.md",
        SERVICE_NAME=service.service_name,
        FAILURE_SECTION="\n\n".join(sections)
        or "## Failure\n\nVerification failed without detail.",
    )


async def _check_tool_use(
    tool_name: str, tool_input: dict[str, Any], context: ToolPermissionContext
) -> PermissionResultAllow | PermissionResultDeny:
    """Gate every tool call. Defence in depth behind the `allowed_tools` list.

    The agent is reading untrusted text, so `Bash` is constrained to an allowlist of programs with
    no shell operators — chaining is how an allowlist normally gets bypassed.
    """
    if tool_name != "Bash":
        return PermissionResultAllow(behavior="allow")

    command = str(tool_input.get("command", "")).strip()

    if _SHELL_OPERATORS.search(command):
        return PermissionResultDeny(
            behavior="deny",
            message=(
                "Shell operators (|, ||, &&, ;, backticks, $(), redirection to absolute paths, "
                "sudo) are not permitted. Run one command at a time."
            ),
        )

    try:
        parts = shlex.split(command)
    except ValueError:
        return PermissionResultDeny(behavior="deny", message="Command could not be parsed.")
    if not parts:
        return PermissionResultDeny(behavior="deny", message="Empty command.")

    program = Path(parts[0]).name
    if program not in _ALLOWED_COMMANDS:
        return PermissionResultDeny(
            behavior="deny",
            message=(
                f"{program!r} is not an permitted command. Allowed: "
                f"{', '.join(sorted(_ALLOWED_COMMANDS))}."
            ),
        )

    if program == "git":
        subcommand = next((p for p in parts[1:] if not p.startswith("-")), "")
        if subcommand not in _ALLOWED_GIT:
            return PermissionResultDeny(
                behavior="deny",
                message=(
                    f"git {subcommand!r} is not permitted. This agent does not push or modify git "
                    "configuration; the orchestrator handles that after verification. Allowed: "
                    f"{', '.join(sorted(_ALLOWED_GIT))}."
                ),
            )

    return PermissionResultAllow(behavior="allow")


def _agent_options(settings: Settings, worktree: Path) -> ClaudeAgentOptions:
    notion_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",  # noqa: S108
        "NOTION_TOKEN": resolve_secret(settings.notion_token),
    }
    return ClaudeAgentOptions(
        model=settings.agent_model,
        cwd=str(worktree),
        allowed_tools=_ALLOWED_TOOLS,
        # Blocked explicitly as well as by omission, so a future SDK default cannot re-enable them.
        disallowed_tools=["WebFetch", "WebSearch", "NotebookEdit"],
        permission_mode="acceptEdits",
        can_use_tool=_check_tool_use,
        # `xhigh` is the recommended effort for coding and agentic work on Opus 4.8.
        effort=settings.agent_effort,  # type: ignore[arg-type]
        thinking=ThinkingConfigAdaptive(type="adaptive"),
        max_turns=120,
        # Read-only Notion access, so the agent can pull owner/team for the OCI labels.
        mcp_servers={
            "notion": {
                "type": "stdio",
                "command": settings.notion_mcp_command,
                "args": settings.notion_mcp_args,
                "env": notion_env,
            }
        },
        # Do not inherit the host's CLAUDE.md or settings; the agent runs on exactly this prompt.
        setting_sources=None,
        env={
            "ANTHROPIC_API_KEY": resolve_secret(settings.anthropic_api_key),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/tmp",  # noqa: S108
        },
    )


def parse_report(text: str) -> AgentReport:
    """Extract the JSON report from the agent's final message.

    Takes the last JSON block, since the agent may quote example JSON earlier in its reply.
    """
    report = AgentReport(raw=text)
    matches = _JSON_BLOCK.findall(text)
    if not matches:
        logger.warning("Agent final message contained no JSON report block")
        report.summary = text.strip()[:2000]
        return report

    try:
        payload = json.loads(matches[-1])
    except json.JSONDecodeError:
        logger.warning("Agent JSON report block was not valid JSON")
        report.summary = text.strip()[:2000]
        return report

    report.status = str(payload.get("status") or "FIXED")
    report.summary = str(payload.get("summary") or "")
    report.changes = [str(c) for c in payload.get("changes") or []]
    report.multistage = bool(payload.get("multistage"))
    report.tests_added = bool(payload.get("tests_added"))
    report.tests_rationale = str(payload.get("tests_rationale") or "")
    report.notes = [str(n) for n in payload.get("notes") or []]
    blocked = payload.get("blocked_reason")
    report.blocked_reason = str(blocked) if blocked else None
    return report


async def run_agent(settings: Settings, worktree: Path, prompt: str) -> AgentReport:
    """Run one agent turn to completion and return its parsed report."""
    final_text = ""
    result: ResultMessage | None = None

    async for message in query(prompt=prompt, options=_agent_options(settings, worktree)):
        match message:
            case AssistantMessage(content=content):
                text = "".join(b.text for b in content if isinstance(b, TextBlock))
                if text.strip():
                    final_text = text
            case ResultMessage() as res:
                result = res

    if result is None:
        raise AgentError("Agent produced no result message")
    if result.is_error:
        raise AgentError(f"Agent run failed: {result.stop_reason or 'unknown error'}")

    report = parse_report(result.result or final_text)
    report.cost_usd = result.total_cost_usd
    report.turns = result.num_turns
    logger.info(
        "Agent finished: status=%s turns=%s cost=$%.4f",
        report.status,
        report.turns,
        report.cost_usd or 0.0,
    )
    return report
