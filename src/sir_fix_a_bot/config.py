"""Configuration and secret resolution.

Every secret-bearing setting accepts either a literal value (local development) or a Secret Manager
resource name (`projects/<p>/secrets/<s>/versions/latest`). Production sets the resource names, so
no secret material lands in the Cloud Run environment or in a `.env` file.
"""

from __future__ import annotations

import functools
import logging
import re
from typing import Annotated

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

_SECRET_RESOURCE = re.compile(r"^projects/[^/]+/secrets/[^/]+/versions/[^/]+$")

#: A setting that is either a literal secret or a Secret Manager resource name.
SecretRef = Annotated[SecretStr, Field(min_length=1)]


class Settings(BaseSettings):
    """Process configuration, populated from the environment.

    Fields typed `SecretRef` are passed through `resolve_secret` at point of use, never at import,
    so that a missing Secret Manager permission surfaces as a clear runtime error rather than a
    failure to start.
    """

    model_config = SettingsConfigDict(
        env_prefix="SFB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Google Cloud -----------------------------------------------------------------
    gcp_project: str
    gcp_region: str = "europe-west2"
    #: Cloud Tasks queue that feeds the worker.
    tasks_queue: str = "sir-fix-a-bot"
    #: Fully-qualified worker URL that Cloud Tasks POSTs to.
    worker_url: str = ""
    #: Service account Cloud Tasks mints OIDC tokens for when calling the worker.
    tasks_invoker_sa: str = ""
    firestore_database: str = "(default)"
    firestore_collection: str = "runs"

    # --- Wiz --------------------------------------------------------------------------
    wiz_auth_url: str = "https://auth.app.wiz.io/oauth/token"
    #: Region-specific GraphQL endpoint, e.g. https://api.eu17.app.wiz.io/graphql
    wiz_api_url: str
    wiz_client_id: SecretRef
    wiz_client_secret: SecretRef
    #: Shared secret Wiz sends on the webhook, compared in constant time.
    wiz_webhook_secret: SecretRef
    #: Findings below this severity are dropped at intake.
    wiz_min_severity: str = "HIGH"

    # --- Notion -----------------------------------------------------------------------
    #: Internal integration secret (`ntn_...`). The hosted Notion MCP is OAuth-browser-only and
    #: unusable headless, so we self-host `@notionhq/notion-mcp-server` over stdio with this.
    notion_token: SecretRef
    #: Notion database id of the CMDB.
    notion_cmdb_database_id: str
    #: Command used to launch the stdio MCP server. In the deployed image the server is npm-installed
    #: and version-pinned at build time, so this points at the local binary rather than fetching via
    #: `npx -y` on every run.
    notion_mcp_command: str = "npx"
    notion_mcp_args: list[str] = Field(default_factory=lambda: ["-y", "@notionhq/notion-mcp-server"])

    # CMDB column names. Notion property names are free text and differ per workspace, so they are
    # configuration rather than constants.
    notion_prop_service: str = "Service Name"
    notion_prop_repo: str = "GitHub Repo"
    notion_prop_owner: str = "Owner"
    notion_prop_team: str = "Team"
    notion_prop_branch: str = "Default Branch"
    notion_prop_dockerfile: str = "Dockerfile Path"

    # --- GitHub -----------------------------------------------------------------------
    github_app_id: str
    github_app_private_key: SecretRef
    github_api_url: str = "https://api.github.com"
    #: Label applied to every PR and issue we open, used for dedupe and for humans to filter.
    github_label: str = "sir-fix-a-bot"

    # --- Anthropic --------------------------------------------------------------------
    anthropic_api_key: SecretRef
    agent_model: str = "claude-opus-4-8"
    #: `xhigh` is the recommended effort for coding and agentic work on Opus 4.8.
    agent_effort: str = "xhigh"
    agent_max_tokens: int = 64000
    #: Wall-clock ceiling for one agent run, in seconds.
    agent_timeout_s: int = 900

    # --- Behaviour --------------------------------------------------------------------
    #: Directory the worker clones repos into. Wiped after each run.
    worktree_root: str = "/tmp/sfb-worktrees"  # noqa: S108 - container-local scratch, not shared
    #: Number of repair turns granted after a gate or build failure before giving up.
    repair_attempts: int = 1
    dry_run: bool = False


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings once per process."""
    return Settings()  # type: ignore[call-arg]  # values come from the environment


@functools.lru_cache(maxsize=32)
def _fetch_secret_version(resource: str) -> str:
    from google.cloud import secretmanager

    client = secretmanager.SecretManagerServiceClient()
    response = client.access_secret_version(request={"name": resource})
    return response.payload.data.decode("utf-8")


def resolve_secret(value: SecretStr) -> str:
    """Return the plaintext for a setting that may be a Secret Manager reference.

    A value shaped like `projects/*/secrets/*/versions/*` is fetched from Secret Manager; anything
    else is treated as the literal secret (local development).
    """
    raw = value.get_secret_value()
    if _SECRET_RESOURCE.match(raw):
        return _fetch_secret_version(raw)
    return raw
