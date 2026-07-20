from __future__ import annotations

import base64
from pathlib import Path

import httpx
import pytest
import respx
from pydantic import SecretStr

from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.vcs.github_app import GitHubApp, GitHubError

API = "https://api.github.com"

# Generated for tests only; never used against a real GitHub App.
TEST_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----"""


@pytest.fixture
def gh_settings(settings: Settings) -> Settings:
    # model_copy bypasses validation, so the SecretStr wrapper must be explicit here.
    return settings.model_copy(update={"github_app_private_key": SecretStr(TEST_KEY)})


def mock_token_endpoints() -> None:
    respx.get(f"{API}/repos/acme/checkout-api/installation").mock(
        return_value=httpx.Response(200, json={"id": 42})
    )
    respx.post(f"{API}/app/installations/42/access_tokens").mock(
        return_value=httpx.Response(201, json={"token": "ghs_testtoken", "expires_at": "2026-01-01"})
    )


class TestInstallationToken:
    @respx.mock
    async def test_token_is_cached_per_repo(self, gh_settings: Settings) -> None:
        mock_token_endpoints()
        async with GitHubApp(gh_settings) as app:
            assert await app.installation_token("acme/checkout-api") == "ghs_testtoken"
            await app.installation_token("acme/checkout-api")

        assert respx.calls.call_count == 2, "second call should reuse the cached token"

    @respx.mock
    async def test_token_request_is_scoped_to_one_repository(self, gh_settings: Settings) -> None:
        """A token valid for every repo in the installation is far more blast radius than we need."""
        mock_token_endpoints()
        async with GitHubApp(gh_settings) as app:
            await app.installation_token("acme/checkout-api")

        request = respx.calls[-1].request
        assert b'"repositories": ["checkout-api"]' in request.content.replace(b'":[', b'": [')

    @respx.mock
    async def test_api_error_surfaces_message_not_body(self, gh_settings: Settings) -> None:
        respx.get(f"{API}/repos/acme/checkout-api/installation").mock(
            return_value=httpx.Response(404, json={"message": "Not Found", "secret": "leak"})
        )
        async with GitHubApp(gh_settings) as app:
            with pytest.raises(GitHubError) as exc:
                await app.installation_token("acme/checkout-api")

        assert "Not Found" in str(exc.value)
        assert "leak" not in str(exc.value)


class TestGitCredentialHandling:
    def test_token_never_appears_in_git_config_keys(self, gh_settings: Settings) -> None:
        """The token goes in an extraheader value, not the remote URL, so it cannot persist into
        .git/config where the agent's own Read tool would find it."""
        app = GitHubApp(gh_settings)
        env = app._git_env("ghs_secret")

        assert env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
        expected = base64.b64encode(b"x-access-token:ghs_secret").decode()
        assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: Basic {expected}"
        assert env["GIT_TERMINAL_PROMPT"] == "0"

    def test_git_env_does_not_leak_process_environment(self, gh_settings: Settings) -> None:
        app = GitHubApp(gh_settings)
        assert set(app._git_env("t")) == {
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_TERMINAL_PROMPT",
        }


class TestGitOperations:
    """Exercised against a real local git repo — the subprocess plumbing is what breaks."""

    @pytest.fixture
    async def repo(self, tmp_path: Path, gh_settings: Settings) -> Path:
        app = GitHubApp(gh_settings)
        work = tmp_path / "repo"
        work.mkdir()
        await app._git("init", "-q", "-b", "main", cwd=work)
        (work / "Dockerfile").write_text("FROM python:3.11-slim\n")
        await app._git("add", "-A", cwd=work)
        await app._git("commit", "-q", "-m", "initial", cwd=work)
        return work

    async def test_has_changes_reflects_worktree_state(
        self, repo: Path, gh_settings: Settings
    ) -> None:
        app = GitHubApp(gh_settings)
        assert not await app.has_changes(repo)

        (repo / "Dockerfile").write_text("FROM python:3.11.14-slim\n")
        assert await app.has_changes(repo)

    async def test_diff_includes_modified_and_new_files(
        self, repo: Path, gh_settings: Settings
    ) -> None:
        app = GitHubApp(gh_settings)
        (repo / "Dockerfile").write_text("FROM python:3.11.14-slim\n")
        (repo / "tests").mkdir()
        (repo / "tests" / "test_new.py").write_text("def test_x(): assert True\n")

        diff = await app.diff(repo)

        assert "-FROM python:3.11-slim" in diff
        assert "+FROM python:3.11.14-slim" in diff
        # Untracked files must appear too, or the gate would never see added tests.
        assert "tests/test_new.py" in diff

    async def test_failed_git_command_raises_with_stderr(
        self, tmp_path: Path, gh_settings: Settings
    ) -> None:
        app = GitHubApp(gh_settings)
        empty = tmp_path / "not-a-repo"
        empty.mkdir()
        with pytest.raises(GitHubError, match="git status failed"):
            await app._git("status", cwd=empty)
