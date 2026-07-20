from __future__ import annotations

import json
from pathlib import Path

from sir_fix_a_bot.verify.cloudbuild import build_config, detect_test_command


class TestDetectTestCommand:
    def test_python_project_with_tests_dir(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        (tmp_path / "tests").mkdir()
        assert detect_test_command(tmp_path) == ["python", "-m", "pytest", "-q"]

    def test_python_project_with_root_level_tests(self, tmp_path: Path) -> None:
        (tmp_path / "setup.py").write_text("")
        (tmp_path / "test_app.py").write_text("")
        assert detect_test_command(tmp_path) == ["python", "-m", "pytest", "-q"]

    def test_python_project_without_any_tests(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        assert detect_test_command(tmp_path) is None

    def test_node_project_with_test_script(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "jest"}}))
        assert detect_test_command(tmp_path) == ["npm", "test", "--silent"]

    def test_node_project_without_test_script(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps({"scripts": {"build": "tsc"}}))
        assert detect_test_command(tmp_path) is None

    def test_malformed_package_json_does_not_raise(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text("{not json")
        assert detect_test_command(tmp_path) is None

    def test_go_and_rust_projects(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text("module x\n")
        assert detect_test_command(tmp_path) == ["go", "test", "./..."]

        rust = tmp_path / "rust"
        rust.mkdir()
        (rust / "Cargo.toml").write_text("[package]\nname='x'\n")
        assert detect_test_command(rust) == ["cargo", "test"]

    def test_unrecognised_project(self, tmp_path: Path) -> None:
        assert detect_test_command(tmp_path) is None


class TestBuildConfig:
    def test_never_pushes_the_built_image(self) -> None:
        """A half-fixed image must not become pullable as a side effect of verifying it."""
        config = build_config("Dockerfile", "verify:abc", ["python", "-m", "pytest"])
        assert "images" not in config

    def test_build_step_uses_the_declared_dockerfile_path(self) -> None:
        config = build_config("services/api/Dockerfile", "verify:abc", None)
        build = config["steps"][0]  # type: ignore[index]
        assert build["args"] == ["build", "-f", "services/api/Dockerfile", "-t", "verify:abc", "."]

    def test_tests_run_inside_the_built_image(self) -> None:
        """Running tests against the source tree would not catch a dropped runtime dependency."""
        config = build_config("Dockerfile", "verify:abc", ["python", "-m", "pytest", "-q"])
        steps = config["steps"]  # type: ignore[index]

        assert len(steps) == 2
        test = steps[1]
        assert test["args"][:2] == ["run", "--rm"]
        assert "verify:abc" in test["args"]
        assert test["args"][-3:] == ["python", "-m", "pytest", "-q"][-3:]
        assert test["waitFor"] == ["build"]

    def test_entrypoint_is_overridden_so_cmd_does_not_run_instead(self) -> None:
        config = build_config("Dockerfile", "verify:abc", ["pytest"])
        test = config["steps"][1]  # type: ignore[index]
        args = test["args"]
        assert args[args.index("--entrypoint") + 1] == ""

    def test_build_only_when_no_test_command(self) -> None:
        config = build_config("Dockerfile", "verify:abc", None)
        assert len(config["steps"]) == 1  # type: ignore[arg-type]

    def test_timeout_is_bounded(self) -> None:
        """The whole run must stay inside the Cloud Tasks 30-minute dispatch deadline."""
        config = build_config("Dockerfile", "verify:abc", None)
        assert config["timeout"].endswith("s")  # type: ignore[union-attr]
        assert int(str(config["timeout"]).rstrip("s")) <= 900
