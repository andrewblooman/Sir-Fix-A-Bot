from __future__ import annotations

import pytest

from sir_fix_a_bot.config import Settings


@pytest.fixture
def settings() -> Settings:
    """Settings with literal (non-Secret-Manager) values, so nothing reaches out to GCP."""
    return Settings(
        gcp_project="test-project",
        wiz_api_url="https://api.test.app.wiz.io/graphql",
        wiz_client_id="test-client-id",  # type: ignore[arg-type]
        wiz_client_secret="test-client-secret",  # type: ignore[arg-type]
        wiz_webhook_secret="test-webhook-secret",  # type: ignore[arg-type]
        notion_token="ntn_test",  # type: ignore[arg-type]
        notion_cmdb_database_id="db-123",
        github_app_id="12345",
        github_app_private_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",  # type: ignore[arg-type]
        anthropic_api_key="sk-ant-test",  # type: ignore[arg-type]
    )
