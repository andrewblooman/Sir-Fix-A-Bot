from __future__ import annotations

import httpx
import pytest
import respx

from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.models import Severity
from sir_fix_a_bot.wiz.client import WizClient, WizError, parse_finding

AUTH_URL = "https://auth.app.wiz.io/oauth/token"
API_URL = "https://api.test.app.wiz.io/graphql"

TOKEN_RESPONSE = {"access_token": "tok-abc", "expires_in": 86400, "token_type": "Bearer"}

FINDING_NODE = {
    "id": "wf-001",
    "name": "CVE-2025-12345",
    "description": "Heap overflow in libfoo",
    "severity": "CRITICAL",
    "score": 9.8,
    "fixedVersion": "1.2.4",
    "version": "1.2.3",
    "detailedName": "libfoo",
    "firstDetectedAt": "2026-07-01T10:30:00Z",
    "vulnerableAsset": {
        "id": "asset-1",
        "name": "checkout-api",
        "providerUniqueId": "gcp/run/checkout-api",
        "cloudPlatform": "GCP",
        "subscriptionExternalId": "my-gcp-project",
        "imageId": "europe-west2-docker.pkg.dev/p/r/checkout-api@sha256:abc",
    },
}


class TestParseFinding:
    def test_maps_all_core_fields(self) -> None:
        finding = parse_finding(FINDING_NODE)

        assert finding.id == "wf-001"
        assert finding.cve_id == "CVE-2025-12345"
        assert finding.severity is Severity.CRITICAL
        assert finding.cvss_score == 9.8
        assert finding.package_name == "libfoo"
        assert finding.installed_version == "1.2.3"
        assert finding.fixed_version == "1.2.4"
        assert finding.service_name == "checkout-api"
        assert finding.project_id == "my-gcp-project"
        assert finding.detected_at is not None
        assert finding.detected_at.year == 2026

    def test_non_cve_title_leaves_cve_id_unset(self) -> None:
        node = FINDING_NODE | {"name": "Outdated base image"}
        assert parse_finding(node).cve_id is None

    def test_unknown_severity_degrades_to_medium(self) -> None:
        node = FINDING_NODE | {"severity": "SPICY"}
        assert parse_finding(node).severity is Severity.MEDIUM

    def test_unparseable_timestamp_is_dropped_not_fatal(self) -> None:
        node = FINDING_NODE | {"firstDetectedAt": "not-a-date"}
        assert parse_finding(node).detected_at is None

    def test_serverless_asset_without_image_id(self) -> None:
        """A serverless asset has region but no imageId — the union must be read defensively."""
        node = FINDING_NODE | {
            "vulnerableAsset": {
                "id": "a2",
                "name": "worker-svc",
                "providerUniqueId": "gcp/run/worker-svc",
                "cloudPlatform": "GCP",
                "region": "europe-west2",
            }
        }
        finding = parse_finding(node)
        assert finding.region == "europe-west2"
        assert finding.image_ref == "gcp/run/worker-svc"

    def test_missing_service_name_raises(self) -> None:
        node = FINDING_NODE | {"vulnerableAsset": {}}
        with pytest.raises(WizError, match="no resolvable service name"):
            parse_finding(node)

    def test_fallback_service_name_used_when_asset_anonymous(self) -> None:
        node = FINDING_NODE | {"vulnerableAsset": {}}
        assert parse_finding(node, fallback_service="fallback-svc").service_name == "fallback-svc"


class TestWizClientAuth:
    @respx.mock
    async def test_token_is_cached_across_queries(self, settings: Settings) -> None:
        auth = respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json=TOKEN_RESPONSE))
        respx.post(API_URL).mock(
            return_value=httpx.Response(
                200, json={"data": {"vulnerabilityFindings": {"nodes": [FINDING_NODE]}}}
            )
        )

        async with WizClient(settings) as client:
            await client.get_finding("wf-001")
            await client.get_finding("wf-001")

        assert auth.call_count == 1, "token should be fetched once and reused"

    @respx.mock
    async def test_auth_failure_does_not_leak_body(self, settings: Settings) -> None:
        respx.post(AUTH_URL).mock(
            return_value=httpx.Response(401, json={"error": "bad client_id=leaky"})
        )

        async with WizClient(settings) as client:
            with pytest.raises(WizError) as exc:
                await client.get_finding("wf-001")

        assert "leaky" not in str(exc.value)
        assert "401" in str(exc.value)


class TestWizClientQueries:
    @respx.mock
    async def test_graphql_errors_raise_even_on_http_200(self, settings: Settings) -> None:
        """Wiz signals schema and permission problems in `errors` with a 200 status."""
        respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json=TOKEN_RESPONSE))
        respx.post(API_URL).mock(
            return_value=httpx.Response(
                200, json={"errors": [{"message": "insufficient permissions"}], "data": None}
            )
        )

        async with WizClient(settings) as client:
            with pytest.raises(WizError, match="insufficient permissions"):
                await client.get_finding("wf-001")

    @respx.mock
    async def test_get_finding_returns_none_when_absent(self, settings: Settings) -> None:
        respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json=TOKEN_RESPONSE))
        respx.post(API_URL).mock(
            return_value=httpx.Response(200, json={"data": {"vulnerabilityFindings": {"nodes": []}}})
        )

        async with WizClient(settings) as client:
            assert await client.get_finding("nope") is None

    @respx.mock
    async def test_open_findings_paginates(self, settings: Settings) -> None:
        respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json=TOKEN_RESPONSE))
        pages = [
            httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerabilityFindings": {
                            "nodes": [FINDING_NODE],
                            "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                        }
                    }
                },
            ),
            httpx.Response(
                200,
                json={
                    "data": {
                        "vulnerabilityFindings": {
                            "nodes": [FINDING_NODE | {"id": "wf-002"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }
                    }
                },
            ),
        ]
        respx.post(API_URL).mock(side_effect=pages)

        async with WizClient(settings) as client:
            findings = await client.open_findings_for_service("checkout-api")

        assert [f.id for f in findings] == ["wf-001", "wf-002"]
