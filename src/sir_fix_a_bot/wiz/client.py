"""Wiz GraphQL client.

Auth is OAuth2 client-credentials against `auth.app.wiz.io` with `audience=wiz-api`; the resulting
bearer token is valid for 24h and cached in-process until shortly before expiry. Queries go to the
tenant's region-specific GraphQL endpoint.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any, Self

import httpx

from sir_fix_a_bot.config import Settings, resolve_secret
from sir_fix_a_bot.models import Finding, Severity
from sir_fix_a_bot.wiz.queries import OPEN_FINDINGS_FOR_SERVICE, VULNERABILITY_FINDING_BY_ID

logger = logging.getLogger(__name__)

#: Refresh this many seconds before the token actually expires, so an in-flight request can't
#: straddle the boundary.
_TOKEN_SKEW_S = 300


class WizError(RuntimeError):
    """Wiz returned an error, either at the transport layer or in the GraphQL `errors` array."""


class WizClient:
    """Async Wiz API client. Use as an async context manager."""

    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None) -> None:
        self._settings = settings
        self._http = http or httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=60.0))
        self._owns_http = http is None
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # --- auth -------------------------------------------------------------------------

    async def _access_token(self) -> str:
        """Return a valid bearer token, fetching a new one if the cached token is near expiry."""
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token

        response = await self._http.post(
            self._settings.wiz_auth_url,
            data={
                "grant_type": "client_credentials",
                "audience": "wiz-api",
                "client_id": resolve_secret(self._settings.wiz_client_id),
                "client_secret": resolve_secret(self._settings.wiz_client_secret),
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if response.status_code != httpx.codes.OK:
            # Deliberately does not echo the body — it can contain the client_id.
            raise WizError(f"Wiz token request failed with HTTP {response.status_code}")

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise WizError("Wiz token response contained no access_token")

        expires_in = int(payload.get("expires_in", 86400))
        self._token = str(token)
        self._token_expires_at = time.monotonic() + max(expires_in - _TOKEN_SKEW_S, 60)
        logger.info("Acquired Wiz access token, valid for %ss", expires_in)
        return self._token

    # --- transport --------------------------------------------------------------------

    async def execute(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Run a GraphQL document and return `data`, raising on any GraphQL error.

        Wiz returns HTTP 200 with a populated `errors` array for schema and permission problems, so
        checking the status code alone would silently yield empty results.
        """
        token = await self._access_token()
        response = await self._http.post(
            self._settings.wiz_api_url,
            json={"query": query, "variables": variables},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        if response.status_code != httpx.codes.OK:
            raise WizError(f"Wiz GraphQL request failed with HTTP {response.status_code}")

        body = response.json()
        if errors := body.get("errors"):
            messages = "; ".join(e.get("message", str(e)) for e in errors)
            raise WizError(f"Wiz GraphQL returned errors: {messages}")

        data = body.get("data")
        if data is None:
            raise WizError("Wiz GraphQL response contained no data")
        return dict(data)

    # --- queries ----------------------------------------------------------------------

    async def get_finding(self, finding_id: str) -> Finding | None:
        """Fetch and normalise one finding by its Wiz id."""
        data = await self.execute(
            VULNERABILITY_FINDING_BY_ID,
            {"filterBy": {"id": [finding_id]}, "first": 1},
        )
        nodes = data.get("vulnerabilityFindings", {}).get("nodes") or []
        if not nodes:
            return None
        return parse_finding(nodes[0])

    async def open_findings_for_service(
        self, service_name: str, *, page_size: int = 50, max_pages: int = 20
    ) -> list[Finding]:
        """Fetch all open findings whose vulnerable asset matches `service_name`.

        Used by the worker to batch sibling findings into one PR when a base-image bump would fix
        several at once, and by the CLI for backfills.
        """
        findings: list[Finding] = []
        cursor: str | None = None

        for _ in range(max_pages):
            data = await self.execute(
                OPEN_FINDINGS_FOR_SERVICE,
                {
                    "filterBy": {
                        "status": ["OPEN", "IN_PROGRESS"],
                        "vulnerableAssetName": [service_name],
                    },
                    "first": page_size,
                    "after": cursor,
                },
            )
            block = data.get("vulnerabilityFindings", {})
            for node in block.get("nodes") or []:
                findings.append(parse_finding(node, fallback_service=service_name))

            page_info = block.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
        else:
            logger.warning(
                "Stopped paginating findings for %s after %s pages", service_name, max_pages
            )

        return findings


def parse_finding(node: dict[str, Any], *, fallback_service: str | None = None) -> Finding:
    """Normalise one `vulnerabilityFindings` node into a `Finding`.

    Wiz's `vulnerableAsset` is a union whose members differ by asset type, so every field is read
    defensively — a serverless asset has no `imageId`, a container image has no `region`.
    """
    asset = node.get("vulnerableAsset") or {}

    service_name = asset.get("name") or fallback_service
    if not service_name:
        raise WizError(f"Finding {node.get('id')} has no resolvable service name")

    severity_raw = str(node.get("severity") or "MEDIUM").upper()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        logger.warning("Unknown Wiz severity %r, treating as MEDIUM", severity_raw)
        severity = Severity.MEDIUM

    detected_at: datetime | None = None
    if raw_ts := node.get("firstDetectedAt"):
        try:
            detected_at = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            logger.warning("Unparseable firstDetectedAt %r on finding %s", raw_ts, node.get("id"))

    # Wiz puts the CVE in `name` for CVE-backed findings and a prose title otherwise.
    name = str(node.get("name") or "unknown")
    cve_id = name if name.upper().startswith("CVE-") else None

    return Finding(
        id=str(node["id"]),
        cve_id=cve_id,
        name=name,
        description=str(node.get("description") or ""),
        severity=severity,
        cvss_score=_as_float(node.get("score")),
        package_name=node.get("detailedName"),
        installed_version=node.get("version"),
        fixed_version=node.get("fixedVersion"),
        service_name=str(service_name),
        cloud_provider=str(asset.get("cloudPlatform") or "GCP"),
        project_id=asset.get("subscriptionExternalId"),
        region=asset.get("region"),
        image_ref=asset.get("imageId") or asset.get("providerUniqueId"),
        detected_at=detected_at,
    )


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
