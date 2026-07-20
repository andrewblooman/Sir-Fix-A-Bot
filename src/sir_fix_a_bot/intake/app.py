"""Webhook receiver for Wiz automation rules, and the worker's task endpoint.

Both Cloud Run services run this app; the intake service exposes `/webhook/wiz` and the worker
service exposes `/tasks/remediate`. They are split by which routes the deployment allows, so a
single image serves both.

Intake does as little as possible: verify the shared secret, normalise the payload, drop duplicates,
enqueue, and return 202. Anything slower risks Wiz timing out and re-delivering.
"""

from __future__ import annotations

import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel

from sir_fix_a_bot.config import Settings, get_settings, resolve_secret
from sir_fix_a_bot.intake.dedupe import RunStore
from sir_fix_a_bot.models import Finding, RunStatus, Severity
from sir_fix_a_bot.worker import remediate

logger = logging.getLogger(__name__)

app = FastAPI(title="Sir-Fix-A-Bot", docs_url=None, redoc_url=None, openapi_url=None)


class TaskPayload(BaseModel):
    """What intake enqueues and the worker consumes."""

    finding: Finding


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/wiz", status_code=status.HTTP_202_ACCEPTED)
async def wiz_webhook(
    request: Request,
    x_sfb_token: str | None = Header(default=None),
) -> dict[str, str]:
    """Receive a Wiz automation-rule webhook and enqueue the finding."""
    settings = get_settings()
    _verify_secret(settings, x_sfb_token)

    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON") from exc

    try:
        finding = parse_webhook(payload)
    except ValueError as exc:
        logger.warning("Rejected Wiz webhook: %s", exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    threshold = Severity(settings.wiz_min_severity)
    if not finding.severity >= threshold:
        logger.info(
            "Dropping %s finding %s (below %s)",
            finding.severity.value,
            finding.id,
            threshold.value,
        )
        return {"status": "ignored", "reason": "below severity threshold"}

    store = RunStore(settings)
    should_process, reason = store.should_process(finding)
    if not should_process:
        logger.info("Dropping duplicate %s: %s", finding.dedupe_key, reason)
        return {"status": "duplicate", "reason": reason}

    store.mark(finding, RunStatus.QUEUED, queued_at=datetime.now(UTC))
    _enqueue(settings, finding)
    return {"status": "queued", "dedupe_key": finding.dedupe_key}


@app.post("/tasks/remediate")
async def remediate_task(payload: TaskPayload) -> dict[str, str]:
    """Run the pipeline for one finding. Invoked by Cloud Tasks with an OIDC token.

    Cloud Run enforces the OIDC check ahead of this handler, so there is no signature to verify
    here; the service is deployed without public invoker access.
    """
    settings = get_settings()
    finding = payload.finding
    store = RunStore(settings)

    store.mark(finding, RunStatus.RUNNING, started_at=datetime.now(UTC))
    outcome = await remediate(settings, finding)
    store.record_outcome(outcome)

    logger.info(
        "Finished %s: status=%s pr=%s issue=%s",
        finding.dedupe_key,
        outcome.status.value,
        outcome.pr_url,
        outcome.issue_url,
    )
    return {"status": outcome.status.value, "dedupe_key": finding.dedupe_key}


def _verify_secret(settings: Settings, presented: str | None) -> None:
    """Constant-time comparison of the shared secret Wiz sends."""
    expected = resolve_secret(settings.wiz_webhook_secret)
    if not presented or not hmac.compare_digest(presented, expected):
        # Deliberately terse: a detailed message would help an attacker probe the check.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthorized")


def parse_webhook(payload: dict[str, Any]) -> Finding:
    """Normalise a Wiz automation-rule payload into a `Finding`.

    Wiz automation rules let you author the request body, so the shape is whatever the rule was
    configured to send. This accepts the documented envelope shapes and a flat form, and fails
    loudly rather than inventing a service name — the service name is the join key into the CMDB,
    and a wrong one would target the wrong repository.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")

    # Common envelopes: {"issue": {...}}, {"vulnerability": {...}}, {"finding": {...}}, or flat.
    body: dict[str, Any] = payload
    for key in ("vulnerability", "finding", "issue", "data"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            body = nested
            break

    finding_id = _first(body, "id", "findingId", "vulnerabilityId", "sourceRuleId")
    if not finding_id:
        raise ValueError("payload has no finding id")

    service_name = _first(
        body,
        "serviceName",
        "resourceName",
        "entityName",
        "assetName",
        "vulnerableAssetName",
    ) or _nested(body, ("vulnerableAsset", "name"), ("entity", "name"), ("resource", "name"))
    if not service_name:
        raise ValueError(
            "payload has no Cloud Run service name; the automation rule body must include one "
            "(it is the join key into the Notion CMDB)"
        )

    name = _first(body, "name", "cveId", "title", "vulnerabilityName") or "unknown"
    severity_raw = str(_first(body, "severity", "vulnerabilitySeverity") or "MEDIUM").upper()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        severity = Severity.MEDIUM

    return Finding(
        id=str(finding_id),
        cve_id=name if str(name).upper().startswith("CVE-") else None,
        name=str(name),
        description=str(_first(body, "description", "detailedName") or ""),
        severity=severity,
        cvss_score=_as_float(_first(body, "score", "cvssScore")),
        package_name=_first(body, "detailedName", "packageName", "package"),
        installed_version=_first(body, "version", "installedVersion"),
        fixed_version=_first(body, "fixedVersion", "remediation"),
        service_name=str(service_name),
        project_id=_first(body, "subscriptionExternalId", "projectId"),
        region=_first(body, "region"),
        image_ref=_first(body, "imageId", "providerUniqueId"),
    )


def _first(body: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if (value := body.get(key)) not in (None, ""):
            return value
    return None


def _nested(body: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        cursor: Any = body
        for part in path:
            if not isinstance(cursor, dict):
                cursor = None
                break
            cursor = cursor.get(part)
        if cursor not in (None, ""):
            return cursor
    return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except TypeError, ValueError:
        return None


def _enqueue(settings: Settings, finding: Finding) -> None:
    """Hand the finding to Cloud Tasks, which retries and caps concurrency for us."""
    from google.cloud import tasks_v2

    client = tasks_v2.CloudTasksClient()
    parent = client.queue_path(settings.gcp_project, settings.gcp_region, settings.tasks_queue)

    task = tasks_v2.Task(
        http_request=tasks_v2.HttpRequest(
            http_method=tasks_v2.HttpMethod.POST,
            url=f"{settings.worker_url}/tasks/remediate",
            headers={"Content-Type": "application/json"},
            body=TaskPayload(finding=finding).model_dump_json().encode(),
            oidc_token=tasks_v2.OidcToken(
                service_account_email=settings.tasks_invoker_sa,
                audience=settings.worker_url,
            ),
        ),
        # Deduplicates at the queue level too, for the window Cloud Tasks retains the name.
        name=client.task_path(
            settings.gcp_project,
            settings.gcp_region,
            settings.tasks_queue,
            f"{finding.dedupe_key}-{int(datetime.now(UTC).timestamp()) // 3600}",
        ),
    )
    client.create_task(parent=parent, task=task)
    logger.info("Enqueued %s for %s", finding.dedupe_key, finding.service_name)
