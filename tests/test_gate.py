from __future__ import annotations

import pytest

from sir_fix_a_bot.agent.gate import GateContext, evaluate

VULNERABLE = """\
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "-m", "app"]
"""

LABELS = """\
ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
LABEL org.opencontainers.image.source="https://github.com/acme/checkout-api" \\
      org.opencontainers.image.title="checkout-api" \\
      org.opencontainers.image.description="Payments checkout API" \\
      org.opencontainers.image.vendor="payments" \\
      org.opencontainers.image.revision="${BUILD_REVISION}" \\
      org.opencontainers.image.created="${BUILD_CREATED}"
"""

GOOD_FIX = f"""\
FROM python:3.11.14-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11.14-slim
{LABELS}WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .
CMD ["python", "-m", "app"]
"""


def check(after: str, before: str = VULNERABLE, **kwargs: object) -> list[str]:
    """Run the gate and return the rule names that fired."""
    context = GateContext(
        before_dockerfile=before,
        after_dockerfile=after,
        changed_files=kwargs.pop("changed_files", ["Dockerfile"]),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )
    return [v.rule for v in evaluate(context)]


class TestHappyPath:
    def test_a_correct_fix_passes_cleanly(self) -> None:
        assert check(GOOD_FIX) == []


class TestNoUserRule:
    def test_added_user_instruction_is_rejected(self) -> None:
        """The strongest model prior we fight — rootless is normally best practice."""
        after = GOOD_FIX.replace('CMD ["python"', 'USER appuser\nCMD ["python"')
        assert "added_user" in check(after)

    @pytest.mark.parametrize(
        "command",
        [
            "RUN useradd -m appuser",
            "RUN adduser --disabled-password appuser",
            "RUN groupadd -r appgroup",
            "RUN addgroup -S appgroup",
        ],
    )
    def test_added_user_creation_commands_are_rejected(self, command: str) -> None:
        after = GOOD_FIX.replace(
            "WORKDIR /app\nCOPY --from", f"{command}\nWORKDIR /app\nCOPY --from"
        )
        assert "added_user" in check(after)

    def test_preexisting_user_is_left_alone(self) -> None:
        """The rule is that the agent must not introduce one, not that repos may not have them."""
        before = VULNERABLE.replace('CMD ["python"', 'USER appuser\nCMD ["python"')
        after = GOOD_FIX.replace('CMD ["python"', 'USER appuser\nCMD ["python"')
        assert "added_user" not in check(after, before=before)

    def test_useradd_already_present_is_not_flagged_again(self) -> None:
        before = VULNERABLE.replace("WORKDIR /app", "RUN useradd -m appuser\nWORKDIR /app")
        after = GOOD_FIX.replace(
            "WORKDIR /app\nCOPY --from", "RUN useradd -m appuser\nWORKDIR /app\nCOPY --from"
        )
        assert "added_user" not in check(after, before=before)


class TestRuntimeVersionRule:
    def test_patch_bump_is_allowed(self) -> None:
        assert "runtime_version_changed" not in check(GOOD_FIX)

    def test_minor_bump_is_rejected_for_python(self) -> None:
        assert "runtime_version_changed" in check(GOOD_FIX.replace("3.11.14", "3.12.0"))

    def test_major_bump_is_rejected(self) -> None:
        assert "runtime_version_changed" in check(GOOD_FIX.replace("python:3.11.14", "python:4.0"))

    def test_node_minor_bump_is_allowed(self) -> None:
        """Node's compatibility boundary is the major, so 22.3 -> 22.4 is a routine patch bump.
        Comparing at minor precision would reject exactly the upgrades this tool exists to make."""
        before = "FROM node:22.3.1-slim\nRUN npm ci\n"
        after = f"FROM node:22.4.0-slim AS builder\nRUN npm ci\n\nFROM node:22.4.0-slim\n{LABELS}"
        assert "runtime_version_changed" not in check(after, before=before)

    def test_node_major_bump_is_rejected(self) -> None:
        before = "FROM node:22.3.1-slim\nRUN npm ci\n"
        after = f"FROM node:24.0.0-slim AS builder\nRUN npm ci\n\nFROM node:24.0.0-slim\n{LABELS}"
        assert "runtime_version_changed" in check(after, before=before)

    def test_go_minor_bump_is_rejected(self) -> None:
        """Go versions the language at 1.x, so the minor is the meaningful boundary."""
        before = "FROM golang:1.22\nRUN go build ./...\n"
        after = f"FROM golang:1.23 AS builder\nRUN go build ./...\n\nFROM golang:1.23\n{LABELS}"
        assert "runtime_version_changed" in check(after, before=before)

    def test_unpinning_the_version_is_rejected(self) -> None:
        assert "runtime_version_unpinned" in check(
            GOOD_FIX.replace("python:3.11.14-slim", "python:latest")
        )

    def test_swapping_runtime_stage_for_distroless_is_allowed(self) -> None:
        """A legitimate and encouraged move — distroless tags carry no language version, so the
        builder stage is what holds the pin."""
        after = f"""\
FROM python:3.11.14-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM gcr.io/distroless/python3-debian12
{LABELS}COPY --from=builder /install /usr/local
COPY . .
CMD ["-m", "app"]
"""
        assert check(after) == []

    def test_templating_the_base_image_away_is_rejected(self) -> None:
        """Moving the version into a build ARG would make the pin unverifiable."""
        after = (
            f"ARG BASE=python:3.12\nFROM ${{BASE}}\n{LABELS}RUN pip install -r requirements.txt\n"
        )
        assert "runtime_version_templated" in check(after)


class TestMultistageRule:
    def test_single_stage_with_install_phase_is_rejected(self) -> None:
        after = f"FROM python:3.11.14-slim\n{LABELS}RUN pip install -r requirements.txt\n"
        assert "not_multistage" in check(after)

    def test_single_stage_without_install_phase_is_accepted(self) -> None:
        before = 'FROM python:3.11-slim\nCOPY app.py .\nCMD ["python", "app.py"]\n'
        after = f'FROM python:3.11.14-slim\n{LABELS}COPY app.py .\nCMD ["python", "app.py"]\n'
        assert "not_multistage" not in check(after, before=before)

    def test_regression_from_multistage_to_single_is_rejected(self) -> None:
        before = "FROM python:3.11-slim AS b\nRUN pip install -r r.txt\nFROM python:3.11-slim\n"
        after = f"FROM python:3.11-slim\n{LABELS}RUN pip install -r r.txt\n"
        assert "multistage_regression" in check(after, before=before)

    @pytest.mark.parametrize(
        "install",
        [
            "npm ci",
            "yarn install",
            "apt-get install -y curl",
            "apk add curl",
            "go build ./...",
            "make all",
        ],
    )
    def test_install_markers_across_ecosystems(self, install: str) -> None:
        after = f"FROM python:3.11.14-slim\n{LABELS}RUN {install}\n"
        assert "not_multistage" in check(after)


class TestOciLabelRule:
    def test_missing_labels_are_reported(self) -> None:
        after = GOOD_FIX.replace(LABELS, "")
        assert "missing_oci_labels" in check(after)

    def test_labels_on_builder_stage_do_not_count(self) -> None:
        """Labels must be on the shipped image, not the discarded builder."""
        after = GOOD_FIX.replace(LABELS, "")
        after = after.replace(
            "FROM python:3.11.14-slim AS builder\n",
            f"FROM python:3.11.14-slim AS builder\n{LABELS}",
        )
        assert "missing_oci_labels" in check(after)

    def test_hardcoded_revision_is_rejected(self) -> None:
        """A pinned SHA is wrong the moment it is committed, and wrong provenance misleads whoever
        reads it during an incident."""
        after = GOOD_FIX.replace('image.revision="${BUILD_REVISION}"', 'image.revision="abc123"')
        assert "hardcoded_provenance" in check(after)

    def test_hardcoded_created_timestamp_is_rejected(self) -> None:
        after = GOOD_FIX.replace('image.created="${BUILD_CREATED}"', 'image.created="2026-07-21"')
        assert "hardcoded_provenance" in check(after)

    def test_empty_label_value_counts_as_missing(self) -> None:
        after = GOOD_FIX.replace('image.vendor="payments"', 'image.vendor=""')
        assert "missing_oci_labels" in check(after)


class TestScopeRule:
    @pytest.mark.parametrize(
        "path",
        [
            ".github/workflows/ci.yml",
            "cloudbuild.yaml",
            "terraform/main.tf",
            "infra/prod.tfvars",
            "k8s/deployment.yaml",
            "Jenkinsfile",
        ],
    )
    def test_protected_paths_are_rejected(self, path: str) -> None:
        assert "out_of_scope" in check(GOOD_FIX, changed_files=["Dockerfile", path])

    @pytest.mark.parametrize(
        "path",
        ["Dockerfile", "requirements.txt", "poetry.lock", "src/app.py", "tests/test_app.py"],
    )
    def test_expected_paths_are_allowed(self, path: str) -> None:
        assert "out_of_scope" not in check(GOOD_FIX, changed_files=[path])


class TestBlockedAndEmptyRuns:
    def test_blocked_run_with_a_clean_tree_passes(self) -> None:
        context = GateContext(
            before_dockerfile=VULNERABLE,
            after_dockerfile=VULNERABLE,
            changed_files=[],
            agent_blocked=True,
            has_changes=False,
        )
        assert evaluate(context) == []

    def test_blocked_run_that_left_changes_is_rejected(self) -> None:
        context = GateContext(
            before_dockerfile=VULNERABLE,
            after_dockerfile=GOOD_FIX,
            changed_files=["Dockerfile"],
            agent_blocked=True,
            has_changes=True,
        )
        assert [v.rule for v in evaluate(context)] == ["blocked_with_changes"]

    def test_claiming_success_with_no_changes_is_rejected(self) -> None:
        context = GateContext(
            before_dockerfile=VULNERABLE,
            after_dockerfile=VULNERABLE,
            changed_files=[],
            has_changes=False,
        )
        assert [v.rule for v in evaluate(context)] == ["no_changes"]


class TestViolationRendering:
    def test_violations_carry_actionable_text_for_the_repair_turn(self) -> None:
        after = GOOD_FIX.replace('CMD ["python"', 'USER appuser\nCMD ["python"')
        context = GateContext(
            before_dockerfile=VULNERABLE, after_dockerfile=after, changed_files=["Dockerfile"]
        )
        violation = next(v for v in evaluate(context) if v.rule == "added_user")

        assert "USER appuser" in violation.message
        assert violation.line is not None
        assert "[added_user]" in violation.render()
