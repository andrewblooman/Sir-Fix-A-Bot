"""GitHub App authentication and repository operations.

A GitHub App is used rather than a PAT so that every token is scoped to a single repository
installation and expires within the hour. The orchestrator holds these credentials; the agent
never does.

Credentials are handed to git through `GIT_CONFIG_*` environment variables rather than embedded in
the remote URL. A token in the URL persists into `.git/config`, the reflog and any error output,
and would then be readable by the agent's own tools inside the same worktree.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Self

import httpx
import jwt

from sir_fix_a_bot.config import Settings, resolve_secret

logger = logging.getLogger(__name__)

#: GitHub rejects app JWTs with more than 10 minutes of life; stay well inside that.
_JWT_TTL_S = 540
#: Refresh installation tokens this long before their stated expiry.
_TOKEN_SKEW_S = 300
_GIT_TIMEOUT_S = 300


class GitHubError(RuntimeError):
    """A GitHub API call or git subprocess failed."""


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str


class GitHubApp:
    """GitHub App client: installation tokens, clone/branch/push, PRs and issues."""

    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._http = http or httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=60.0))
        self._owns_http = http is None
        #: repo_full_name -> (token, monotonic expiry)
        self._tokens: dict[str, tuple[str, float]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # --- auth -------------------------------------------------------------------------

    def _app_jwt(self) -> str:
        now = int(time.time())
        return jwt.encode(
            {"iat": now - 60, "exp": now + _JWT_TTL_S, "iss": self._settings.github_app_id},
            resolve_secret(self._settings.github_app_private_key),
            algorithm="RS256",
        )

    async def _api(
        self,
        method: str,
        path: str,
        *,
        token: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200, 201),
    ) -> Any:
        response = await self._http.request(
            method,
            f"{self._settings.github_api_url}{path}",
            json=json_body,
            params=params,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if response.status_code not in expected:
            # `message` is safe to surface; the full body can echo request content.
            detail = ""
            with contextlib.suppress(ValueError):
                detail = str(response.json().get("message", ""))
            raise GitHubError(f"GitHub {method} {path} -> HTTP {response.status_code} {detail}")
        return response.json() if response.content else None

    async def installation_token(self, repo_full_name: str) -> str:
        """Return a repository-scoped installation token, cached until near expiry."""
        cached = self._tokens.get(repo_full_name)
        if cached and time.monotonic() < cached[1]:
            return cached[0]

        app_jwt = self._app_jwt()
        installation = await self._api(
            "GET", f"/repos/{repo_full_name}/installation", token=app_jwt
        )
        installation_id = installation["id"]

        created = await self._api(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            token=app_jwt,
            json_body={"repositories": [repo_full_name.split("/", 1)[1]]},
            expected=(201,),
        )
        token = str(created["token"])
        # Installation tokens last an hour; cache a little short of that.
        self._tokens[repo_full_name] = (token, time.monotonic() + 3600 - _TOKEN_SKEW_S)
        logger.info("Minted installation token for %s", repo_full_name)
        return token

    def _git_env(self, token: str) -> dict[str, str]:
        """Environment that authenticates git without persisting the token anywhere.

        `GIT_CONFIG_*` applies the header for this process only — unlike a token embedded in the
        remote URL, nothing is written to `.git/config` that the agent could later read.
        """
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        return {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
            "GIT_TERMINAL_PROMPT": "0",
        }

    # --- git --------------------------------------------------------------------------

    async def _git(
        self, *args: str, cwd: Path, token: str | None = None, check: bool = True
    ) -> str:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108
            "GIT_AUTHOR_NAME": "sir-fix-a-bot",
            "GIT_AUTHOR_EMAIL": "sir-fix-a-bot@users.noreply.github.com",
            "GIT_COMMITTER_NAME": "sir-fix-a-bot",
            "GIT_COMMITTER_EMAIL": "sir-fix-a-bot@users.noreply.github.com",
        }
        if token:
            env |= self._git_env(token)

        process = await asyncio.create_subprocess_exec(
            "git",
            *args,
            cwd=str(cwd),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=_GIT_TIMEOUT_S)
        except TimeoutError:
            process.kill()
            raise GitHubError(f"git {args[0]} timed out after {_GIT_TIMEOUT_S}s") from None

        if check and process.returncode != 0:
            # git echoes the remote URL on failure but never the extraheader, so stderr is safe.
            raise GitHubError(f"git {args[0]} failed: {stderr.decode(errors='replace').strip()}")
        return stdout.decode(errors="replace")

    async def clone(self, repo_full_name: str, dest: Path, *, branch: str = "main") -> Path:
        """Shallow-clone `repo_full_name` into `dest`.

        The clone is deliberately shallow and blobless: Cloud Run's filesystem is tmpfs and counts
        against the instance memory limit, so a full history of a large repo would exhaust it.
        """
        token = await self.installation_token(repo_full_name)
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)

        await self._git(
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--branch",
            branch,
            "--single-branch",
            f"https://github.com/{repo_full_name}.git",
            str(dest),
            cwd=dest.parent,
            token=token,
        )
        logger.info("Cloned %s@%s into %s", repo_full_name, branch, dest)
        return dest

    async def diff(self, worktree: Path) -> str:
        """Return the unstaged+untracked diff of the worktree, as the gate sees it."""
        await self._git("add", "-A", "--intent-to-add", cwd=worktree)
        return await self._git("diff", cwd=worktree)

    async def has_changes(self, worktree: Path) -> bool:
        return bool((await self._git("status", "--porcelain", cwd=worktree)).strip())

    async def commit_and_push(
        self, worktree: Path, repo_full_name: str, branch: str, message: str
    ) -> None:
        """Create `branch`, commit everything in the worktree, and push it."""
        token = await self.installation_token(repo_full_name)
        await self._git("checkout", "-B", branch, cwd=worktree)
        await self._git("add", "-A", cwd=worktree)
        await self._git("commit", "-m", message, cwd=worktree)
        await self._git("push", "--force-with-lease", "origin", branch, cwd=worktree, token=token)
        logger.info("Pushed %s to %s", branch, repo_full_name)

    # --- pull requests and issues -----------------------------------------------------

    async def find_open_pr(self, repo_full_name: str, branch: str) -> PullRequest | None:
        """Return an already-open PR for `branch`, if any.

        Wiz re-fires the same finding on every rescan, so this is the second line of defence
        against opening a duplicate PR after the Firestore record has aged out.
        """
        token = await self.installation_token(repo_full_name)
        owner = repo_full_name.split("/", 1)[0]
        results = await self._api(
            "GET",
            f"/repos/{repo_full_name}/pulls",
            token=token,
            params={"state": "open", "head": f"{owner}:{branch}"},
        )
        if not results:
            return None
        return PullRequest(number=results[0]["number"], url=results[0]["html_url"])

    async def open_pull_request(
        self,
        repo_full_name: str,
        *,
        branch: str,
        base: str,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> PullRequest:
        token = await self.installation_token(repo_full_name)
        created = await self._api(
            "POST",
            f"/repos/{repo_full_name}/pulls",
            token=token,
            json_body={"title": title, "head": branch, "base": base, "body": body},
            expected=(201,),
        )
        pr = PullRequest(number=created["number"], url=created["html_url"])
        await self._apply_labels(repo_full_name, pr.number, labels, token)
        logger.info("Opened PR %s", pr.url)
        return pr

    async def open_issue(
        self,
        repo_full_name: str,
        *,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> str:
        """File an issue for a finding we could not fix, so the backlog stays visible."""
        token = await self.installation_token(repo_full_name)
        created = await self._api(
            "POST",
            f"/repos/{repo_full_name}/issues",
            token=token,
            json_body={
                "title": title,
                "body": body,
                "labels": labels or [self._settings.github_label],
            },
            expected=(201,),
        )
        return str(created["html_url"])

    async def _apply_labels(
        self, repo_full_name: str, number: int, labels: list[str] | None, token: str
    ) -> None:
        wanted = labels or [self._settings.github_label]
        try:
            await self._api(
                "POST",
                f"/repos/{repo_full_name}/issues/{number}/labels",
                token=token,
                json_body={"labels": wanted},
            )
        except GitHubError as exc:
            # A missing label in the target repo must not sink an otherwise good PR.
            logger.warning("Could not label %s#%s: %s", repo_full_name, number, exc)
