"""Verify a fix by building the image and running the tests inside it.

Cloud Run cannot host a privileged Docker daemon, so the build is delegated to Cloud Build. The
build config deliberately omits the `images` key, so nothing is pushed to a registry — this is a
verification build, and a half-fixed image must not become pullable.

Tests run *inside the built image* rather than against the source tree. That is the only thing that
proves a multi-stage rewrite did not drop a runtime dependency: a missing shared library or an
unpropagated site-packages directory fails at container start, not at build time.

The Cloud Build API client is used rather than the `gcloud` CLI, which would add roughly a gigabyte
to the worker image for a single API call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.models import VerificationResult

logger = logging.getLogger(__name__)

#: Cap the excerpt fed back to the agent; a full build log would swamp its context.
_EXCERPT_CHARS = 4000
#: Stay inside the Cloud Tasks 30-minute dispatch deadline, leaving room for the agent turns.
_BUILD_TIMEOUT_S = 600
_POLL_INTERVAL_S = 10


class VerificationError(RuntimeError):
    """The verification build could not be run at all (as distinct from failing)."""


def detect_test_command(worktree: Path) -> list[str] | None:
    """Infer how to run this repository's tests, or None when it has no suite.

    Returns a shell-free argv so the command can run as the image's entrypoint override.
    """
    has_python_manifest = (worktree / "pyproject.toml").exists() or (worktree / "setup.py").exists()
    has_python_tests = (worktree / "tests").is_dir() or list(worktree.glob("test_*.py"))
    if has_python_manifest and has_python_tests:
        return ["python", "-m", "pytest", "-q"]

    if (package := worktree / "package.json").exists():
        try:
            scripts = json.loads(package.read_text()).get("scripts", {})
        except json.JSONDecodeError, OSError:
            scripts = {}
        if "test" in scripts:
            return ["npm", "test", "--silent"]

    if (worktree / "go.mod").exists():
        return ["go", "test", "./..."]

    if (worktree / "Cargo.toml").exists():
        return ["cargo", "test"]

    return None


def build_config(
    dockerfile_path: str, image_tag: str, test_command: list[str] | None
) -> dict[str, object]:
    """Generate the Cloud Build config.

    No `images` key: the image is built and discarded, never pushed. A vulnerable-but-unverified
    image must not end up in the registry as a side effect of checking a fix.
    """
    steps: list[dict[str, object]] = [
        {
            "id": "build",
            "name": "gcr.io/cloud-builders/docker",
            "args": ["build", "-f", dockerfile_path, "-t", image_tag, "."],
        }
    ]

    if test_command:
        steps.append(
            {
                "id": "test",
                "name": "gcr.io/cloud-builders/docker",
                # `--entrypoint ""` so the image's own CMD does not run instead of the tests.
                "args": ["run", "--rm", "--entrypoint", "", image_tag, *test_command],
                "waitFor": ["build"],
            }
        )

    return {
        "steps": steps,
        "timeout": f"{_BUILD_TIMEOUT_S}s",
        "options": {"logging": "CLOUD_LOGGING_ONLY", "machineType": "E2_HIGHCPU_8"},
    }


async def verify(settings: Settings, worktree: Path, dockerfile_path: str) -> VerificationResult:
    """Build the image and run the tests inside it, returning a structured result."""
    test_command = detect_test_command(worktree)
    if test_command is None:
        logger.info("No test suite detected in %s; verifying the build only", worktree)

    image_tag = f"sir-fix-a-bot-verify:{uuid.uuid4().hex[:12]}"
    config = build_config(dockerfile_path, image_tag, test_command)

    return await asyncio.to_thread(_run_build, settings, worktree, config, bool(test_command))


def _run_build(
    settings: Settings, worktree: Path, config: dict[str, object], has_tests: bool
) -> VerificationResult:
    """Upload the worktree and run the build. Blocking; called via `asyncio.to_thread`."""
    from google.cloud import storage
    from google.cloud.devtools import cloudbuild_v1

    source_object = f"sir-fix-a-bot/{uuid.uuid4().hex}.tgz"
    bucket_name = f"{settings.gcp_project}_cloudbuild"

    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "source.tgz"
        _archive_worktree(worktree, archive)

        storage_client = storage.Client(project=settings.gcp_project)
        blob = storage_client.bucket(bucket_name).blob(source_object)
        blob.upload_from_filename(str(archive))

    build = cloudbuild_v1.Build(
        source=cloudbuild_v1.Source(
            storage_source=cloudbuild_v1.StorageSource(bucket=bucket_name, object_=source_object)
        ),
        **config,  # type: ignore[arg-type]
    )

    client = cloudbuild_v1.CloudBuildClient()
    operation = client.create_build(project_id=settings.gcp_project, build=build)
    build_id = operation.metadata.build.id
    log_url = operation.metadata.build.log_url
    logger.info("Cloud Build %s started", build_id)

    result = _await_build(client, settings.gcp_project, build_id)
    return _to_result(result, build_id, log_url, has_tests)


def _archive_worktree(worktree: Path, archive: Path) -> None:
    """Tar the worktree, excluding VCS metadata and local virtualenvs."""
    excluded = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}

    def _filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        parts = Path(info.name).parts
        return None if any(part in excluded for part in parts) else info

    with tarfile.open(archive, "w:gz") as tar:
        tar.add(worktree, arcname=".", filter=_filter)


def _await_build(client: object, project: str, build_id: str) -> object:
    """Poll until the build reaches a terminal status or the local deadline passes."""
    from google.cloud.devtools import cloudbuild_v1

    terminal = {
        cloudbuild_v1.Build.Status.SUCCESS,
        cloudbuild_v1.Build.Status.FAILURE,
        cloudbuild_v1.Build.Status.INTERNAL_ERROR,
        cloudbuild_v1.Build.Status.TIMEOUT,
        cloudbuild_v1.Build.Status.CANCELLED,
        cloudbuild_v1.Build.Status.EXPIRED,
    }
    deadline = time.monotonic() + _BUILD_TIMEOUT_S + 120

    while time.monotonic() < deadline:
        current = client.get_build(project_id=project, id=build_id)  # type: ignore[attr-defined]
        if current.status in terminal:
            return current
        time.sleep(_POLL_INTERVAL_S)

    raise VerificationError(f"Cloud Build {build_id} did not finish within the deadline")


def _to_result(build: object, build_id: str, log_url: str, has_tests: bool) -> VerificationResult:
    """Map a finished build to a `VerificationResult`, attributing failure to build or test."""
    from google.cloud.devtools import cloudbuild_v1

    status = build.status  # type: ignore[attr-defined]
    steps = list(getattr(build, "steps", []) or [])

    def _step_failed(step_id: str) -> bool:
        for step in steps:
            if step.id == step_id:
                return step.status not in (
                    cloudbuild_v1.Build.Status.SUCCESS,
                    cloudbuild_v1.Build.Status.STATUS_UNKNOWN,
                )
        return False

    if status == cloudbuild_v1.Build.Status.SUCCESS:
        return VerificationResult(
            build_ok=True,
            tests_ok=True,
            build_id=build_id,
            log_url=log_url or None,  # type: ignore[arg-type]
        )

    build_ok = not _step_failed("build")
    # Attribute a whole-build failure to the build step unless the build step demonstrably passed.
    tests_ok = False if has_tests else build_ok

    excerpt = (getattr(build, "status_detail", "") or "").strip()
    if not excerpt:
        excerpt = (
            f"Cloud Build finished with status {cloudbuild_v1.Build.Status(status).name}. "
            f"Full log: {log_url}"
        )

    return VerificationResult(
        build_ok=build_ok,
        tests_ok=tests_ok,
        build_id=build_id,
        log_url=log_url or None,  # type: ignore[arg-type]
        failure_excerpt=excerpt[:_EXCERPT_CHARS],
    )
