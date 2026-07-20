"""Post-condition checks on the agent's diff.

Every rule here is also stated in the agent's prompt. This module is what actually enforces them:
the agent reads attacker-influenceable text, and an instruction in a prompt is not a security
control. A violation is fed back for a single repair turn; if it survives that, the run is abandoned
and reported as an issue rather than a pull request.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sir_fix_a_bot.agent.dockerfile import Dockerfile, Stage, parse
from sir_fix_a_bot.models import GateViolation

logger = logging.getLogger(__name__)

#: Required on the final stage. `revision`/`created` must be build args, checked separately.
REQUIRED_LABELS = (
    "org.opencontainers.image.source",
    "org.opencontainers.image.title",
    "org.opencontainers.image.description",
    "org.opencontainers.image.vendor",
    "org.opencontainers.image.revision",
    "org.opencontainers.image.created",
)

#: Files the fix has no business touching. A change here is either scope creep or an attempt to
#: alter the machinery that reviews the change.
PROTECTED_PATHS = (
    re.compile(r"^\.github/"),
    re.compile(r"(^|/)cloudbuild\.ya?ml$"),
    re.compile(r"(^|/)\.gitlab-ci\.ya?ml$"),
    re.compile(r"(^|/)Jenkinsfile$"),
    re.compile(r"(^|/)skaffold\.ya?ml$"),
    re.compile(r"\.tf(vars)?$"),
    re.compile(r"(^|/)(terraform|infra|infrastructure)/"),
    re.compile(r"(^|/)k8s/"),
    re.compile(r"(^|/)\.git/"),
    re.compile(r"(^|/)(secrets?|credentials?)\."),
)

#: Commands that indicate a build/install phase, so a single-stage image is leaving tooling behind.
_INSTALL_MARKERS = re.compile(
    r"\b(pip3?\s+install|poetry\s+install|uv\s+(pip\s+)?(sync|install)|npm\s+(ci|install)"
    r"|yarn\s+install|pnpm\s+install|apt-get\s+install|apk\s+add|go\s+build|cargo\s+build"
    r"|mvn\s+package|gradle\s+build|make\b)",
    re.IGNORECASE,
)

_USER_CREATION = re.compile(r"\b(useradd|adduser|groupadd|addgroup)\b")
#: `${VAR}` / `$VAR` interpolation, used to detect a build arg standing in for a pinned version.
_ARG_REFERENCE = re.compile(r"\$\{?BUILD_(REVISION|CREATED)\}?")

#: How many version components define a runtime's compatibility boundary, per image family.
#:
#: This is not uniform across languages. Python's breaking boundary is the minor version — 3.11 to
#: 3.12 is a migration — so it is compared at two components. Node and the JVM break on the major
#: only, so `node:22.3` to `node:22.4` is a routine patch bump and must be permitted; comparing
#: those at two components would reject exactly the upgrades this tool exists to make.
_VERSION_PRECISION: dict[str, int] = {
    "node": 1,
    "openjdk": 1,
    "eclipse-temurin": 1,
    "amazoncorretto": 1,
    "ibm-semeru-runtimes": 1,
    "nginx": 1,
    "httpd": 1,
    "redis": 1,
    "postgres": 1,
    "mysql": 1,
    "mariadb": 1,
    "python": 2,
    "golang": 2,
    "ruby": 2,
    "rust": 2,
    "php": 2,
    "perl": 2,
    "elixir": 2,
    "erlang": 2,
    "dotnet/sdk": 2,
    "dotnet/aspnet": 2,
    "dotnet/runtime": 2,
}
#: Compare major and minor unless the family is known to break on the major alone.
_DEFAULT_PRECISION = 2


@dataclass(frozen=True)
class GateContext:
    """Everything the gate inspects."""

    before_dockerfile: str | None
    after_dockerfile: str | None
    changed_files: list[str]
    #: True when the agent reported the fix as blocked; relaxes rules about what must be present.
    agent_blocked: bool = False
    has_changes: bool = True


def evaluate(context: GateContext) -> list[GateViolation]:
    """Return every breached post-condition, most important first."""
    violations: list[GateViolation] = []

    if context.agent_blocked:
        # A blocked run should leave the tree clean; there is nothing else to check.
        if context.has_changes:
            violations.append(
                GateViolation(
                    rule="blocked_with_changes",
                    message=(
                        "The fix was reported as blocked but the worktree still has changes. "
                        "Revert them so the run leaves no partial fix behind."
                    ),
                )
            )
        return violations

    if not context.has_changes:
        violations.append(
            GateViolation(
                rule="no_changes",
                message=(
                    "The fix was reported as complete but nothing changed. Either make the change "
                    "or report the fix as blocked with a reason."
                ),
            )
        )
        return violations

    violations.extend(_check_scope(context.changed_files))

    if context.after_dockerfile is None:
        return violations

    after = parse(context.after_dockerfile)
    before = parse(context.before_dockerfile) if context.before_dockerfile else None

    violations.extend(_check_no_user(before, after))
    violations.extend(_check_runtime_version(before, after))
    violations.extend(_check_multistage(before, after))
    violations.extend(_check_oci_labels(after))
    return violations


def _check_scope(changed_files: list[str]) -> list[GateViolation]:
    violations = []
    for path in changed_files:
        for pattern in PROTECTED_PATHS:
            if pattern.search(path):
                violations.append(
                    GateViolation(
                        rule="out_of_scope",
                        message=(
                            f"{path} is outside the scope of a vulnerability fix. CI, "
                            "infrastructure and deployment configuration must not be modified."
                        ),
                        file=path,
                    )
                )
                break
    return violations


def _check_no_user(before: Dockerfile | None, after: Dockerfile) -> list[GateViolation]:
    """Reject an added `USER` instruction or user-creation command.

    Pre-existing ones are permitted — the rule is that the agent must not introduce them, not that
    the repository must not have them.
    """
    violations: list[GateViolation] = []

    before_users = {i.value.strip() for i in before.instructions("USER")} if before else set()
    for instruction in after.instructions("USER"):
        if instruction.value.strip() not in before_users:
            violations.append(
                GateViolation(
                    rule="added_user",
                    message=(
                        f"A USER instruction was added (`USER {instruction.value.strip()}`). "
                        "Container identity is set by the platform at deploy time, not in the "
                        "image. Remove it."
                    ),
                    line=instruction.line,
                )
            )

    before_run = " ".join(i.value for i in before.instructions("RUN")) if before else ""
    before_creates = set(_USER_CREATION.findall(before_run))
    for instruction in after.instructions("RUN"):
        added = set(_USER_CREATION.findall(instruction.value)) - before_creates
        if added:
            violations.append(
                GateViolation(
                    rule="added_user",
                    message=(
                        f"A user-creation command was added ({', '.join(sorted(added))}). "
                        "Do not create users or groups in the image."
                    ),
                    line=instruction.line,
                )
            )

    return violations


def _precision(image_name: str) -> int:
    """How many version components are compared for this image family."""
    family = image_name.rsplit("/", 1)[-1] if "/" not in image_name else image_name
    for candidate in (image_name, image_name.rsplit("/", 1)[-1], family):
        if candidate in _VERSION_PRECISION:
            return _VERSION_PRECISION[candidate]
    # `mcr.microsoft.com/dotnet/aspnet` and friends carry the family in the last two segments.
    parts = image_name.split("/")
    if len(parts) >= 2 and (tail := "/".join(parts[-2:])) in _VERSION_PRECISION:
        return _VERSION_PRECISION[tail]
    return _DEFAULT_PRECISION


def _truncate(version: tuple[int, int | None] | None, precision: int) -> tuple[int, ...] | None:
    """Reduce a parsed version to the components that define compatibility for its family."""
    if version is None:
        return None
    major, minor = version
    if precision <= 1 or minor is None:
        return (major,)
    return (major, minor)


def _versions_by_image(dockerfile: Dockerfile) -> dict[str, set[tuple[int, ...] | None]]:
    """Map each base image name to the set of compatibility-significant versions it appears with."""
    result: dict[str, set[tuple[int, ...] | None]] = {}
    for stage in dockerfile.stages:
        if stage.is_templated:
            continue
        precision = _precision(stage.image_name)
        result.setdefault(stage.image_name, set()).add(_truncate(stage.version, precision))
    return result


def _check_runtime_version(before: Dockerfile | None, after: Dockerfile) -> list[GateViolation]:
    """Reject a major/minor change to any base image that was already present.

    Compared per image name, so splitting one stage into builder+runtime is fine, and swapping the
    runtime stage for an unversioned distroless image is fine — only a same-family version move is
    a violation.
    """
    if before is None:
        return []

    violations: list[GateViolation] = []
    before_versions = _versions_by_image(before)
    after_versions = _versions_by_image(after)

    for image_name, after_set in after_versions.items():
        before_set = before_versions.get(image_name)
        if before_set is None:
            # A newly introduced image family; there is no prior version to hold it to.
            continue

        known = {v for v in before_set if v is not None}
        if not known:
            continue

        for version in after_set:
            if version is None:
                violations.append(
                    GateViolation(
                        rule="runtime_version_unpinned",
                        message=(
                            f"{image_name} was pinned to "
                            f"{_render_versions(known)} but is now unpinned. Keep the version "
                            "pinned so the runtime cannot drift across a rebuild."
                        ),
                    )
                )
            elif version not in known:
                violations.append(
                    GateViolation(
                        rule="runtime_version_changed",
                        message=(
                            f"{image_name} moved from {_render_versions(known)} to "
                            f"{_render_version(version)}. The runtime major/minor version must not "
                            "change. Patch-level moves are fine; if only a minor bump can clear "
                            "this finding, report the fix as blocked."
                        ),
                    )
                )

    for image_name, before_set in before_versions.items():
        known = {v for v in before_set if v is not None}
        if known and image_name in after_versions:
            continue
        if known and any(s.is_templated for s in after.stages):
            violations.append(
                GateViolation(
                    rule="runtime_version_templated",
                    message=(
                        f"{image_name} was pinned to {_render_versions(known)} but the base image "
                        "is now supplied by a build argument, so the version can no longer be "
                        "verified. Pin it in the Dockerfile."
                    ),
                )
            )
    return violations


def _check_multistage(before: Dockerfile | None, after: Dockerfile) -> list[GateViolation]:
    """Require a multi-stage build when the image has a build or install phase."""
    if after.is_multistage:
        return []

    runs = " ".join(i.value for i in after.instructions("RUN"))
    if not _INSTALL_MARKERS.search(runs):
        return []

    # Only raise this if the Dockerfile was already single-stage — we are asking for an improvement,
    # so it should not fire on a file the agent has just correctly restructured.
    if before is not None and before.is_multistage:
        return [
            GateViolation(
                rule="multistage_regression",
                message=(
                    "The Dockerfile was multi-stage and is now single-stage. Restore the split."
                ),
            )
        ]

    return [
        GateViolation(
            rule="not_multistage",
            message=(
                "This image installs or compiles dependencies but is still a single stage, so "
                "build tooling and package caches ship to production and keep generating findings. "
                "Split it into a builder stage and a runtime stage that copies only the artifacts."
            ),
        )
    ]


def _check_oci_labels(after: Dockerfile) -> list[GateViolation]:
    stage: Stage | None = after.final_stage
    if stage is None:
        return []

    labels = after.labels(stage)
    missing = [name for name in REQUIRED_LABELS if not labels.get(name)]
    violations: list[GateViolation] = []

    if missing:
        violations.append(
            GateViolation(
                rule="missing_oci_labels",
                message=(
                    "The final stage is missing required OCI labels: "
                    f"{', '.join(missing)}. Add them to the final stage."
                ),
                line=stage.line,
            )
        )

    # A hardcoded revision or timestamp is wrong the moment it is committed.
    for name in ("org.opencontainers.image.revision", "org.opencontainers.image.created"):
        value = labels.get(name)
        if value and not _ARG_REFERENCE.search(value) and "$" not in value:
            violations.append(
                GateViolation(
                    rule="hardcoded_provenance",
                    message=(
                        f"{name} is hardcoded to {value!r}. It must reference a build argument "
                        "(such as ${BUILD_REVISION}) so it is accurate for every build."
                    ),
                    line=stage.line,
                )
            )

    return violations


def _render_version(version: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version)


def _render_versions(versions: set[tuple[int, ...]]) -> str:
    return "/".join(sorted(_render_version(v) for v in versions))
