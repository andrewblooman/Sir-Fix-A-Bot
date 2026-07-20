"""Sir-Fix-A-Bot's own images must pass the rules Sir-Fix-A-Bot enforces on everyone else.

If the tool cannot meet its own standard, the standard is wrong or the tool is. Either way it
should fail here rather than in a reviewer's inbox.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sir_fix_a_bot.agent.dockerfile import parse
from sir_fix_a_bot.agent.gate import REQUIRED_LABELS, GateContext, evaluate

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"
DOCKERFILES = sorted(DEPLOY.glob("*.Dockerfile"))


def test_dockerfiles_are_discovered() -> None:
    assert DOCKERFILES, f"no Dockerfiles found under {DEPLOY}"


@pytest.mark.parametrize("path", DOCKERFILES, ids=lambda p: p.name)
class TestOwnImagesPassOurOwnGate:
    def test_passes_the_gate(self, path: Path) -> None:
        violations = evaluate(
            GateContext(
                before_dockerfile=None,
                after_dockerfile=path.read_text(),
                changed_files=[str(path.relative_to(DEPLOY.parent))],
            )
        )
        assert violations == [], "\n".join(v.render() for v in violations)

    def test_is_multistage(self, path: Path) -> None:
        assert parse(path.read_text()).is_multistage

    def test_declares_no_user(self, path: Path) -> None:
        """Identity is set by the Cloud Run service account at deploy time."""
        assert parse(path.read_text()).instructions("USER") == []

    def test_carries_every_required_oci_label(self, path: Path) -> None:
        dockerfile = parse(path.read_text())
        labels = dockerfile.labels(dockerfile.final_stage)  # type: ignore[arg-type]
        assert set(REQUIRED_LABELS) <= set(labels)

    def test_provenance_labels_come_from_build_args(self, path: Path) -> None:
        dockerfile = parse(path.read_text())
        labels = dockerfile.labels(dockerfile.final_stage)  # type: ignore[arg-type]
        assert "$" in labels["org.opencontainers.image.revision"]
        assert "$" in labels["org.opencontainers.image.created"]

    def test_base_images_are_pinned_to_a_patch_version(self, path: Path) -> None:
        """`python:3.14-slim` would drift across rebuilds; the bot demands better of others."""
        for stage in parse(path.read_text()).stages:
            if stage.image_name == "python":
                assert stage.tag and stage.tag.count(".") >= 2, (
                    f"{stage.image} is not pinned to a patch version"
                )
