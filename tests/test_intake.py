from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.intake.app import app, parse_webhook
from sir_fix_a_bot.intake.dedupe import RunStore
from sir_fix_a_bot.models import Finding, RunStatus, Severity

WIZ_PAYLOAD = {
    "vulnerability": {
        "id": "wf-001",
        "name": "CVE-2025-12345",
        "description": "Heap overflow in libfoo",
        "severity": "CRITICAL",
        "score": 9.8,
        "detailedName": "libfoo",
        "version": "1.2.3",
        "fixedVersion": "1.2.4",
        "vulnerableAsset": {"name": "checkout-api"},
    }
}


class TestParseWebhook:
    def test_parses_the_documented_envelope(self) -> None:
        finding = parse_webhook(WIZ_PAYLOAD)

        assert finding.id == "wf-001"
        assert finding.cve_id == "CVE-2025-12345"
        assert finding.severity is Severity.CRITICAL
        assert finding.package_name == "libfoo"
        assert finding.service_name == "checkout-api"

    def test_parses_a_flat_payload(self) -> None:
        flat = {"id": "wf-2", "name": "CVE-2025-1", "severity": "HIGH", "serviceName": "api"}
        assert parse_webhook(flat).service_name == "api"

    @pytest.mark.parametrize(
        "key", ["serviceName", "resourceName", "entityName", "assetName", "vulnerableAssetName"]
    )
    def test_accepts_the_service_name_under_any_documented_key(self, key: str) -> None:
        """Wiz automation rules let you author the body, so the field name varies by rule."""
        payload = {"id": "wf-3", "name": "CVE-1", key: "my-service"}
        assert parse_webhook(payload).service_name == "my-service"

    def test_missing_service_name_is_rejected(self) -> None:
        """The service name is the CMDB join key — inventing one would target the wrong repo."""
        with pytest.raises(ValueError, match="no Cloud Run service name"):
            parse_webhook({"id": "wf-4", "name": "CVE-1"})

    def test_missing_finding_id_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="no finding id"):
            parse_webhook({"serviceName": "api"})

    def test_non_cve_name_leaves_cve_id_unset(self) -> None:
        payload = {"id": "w", "name": "Outdated base image", "serviceName": "api"}
        assert parse_webhook(payload).cve_id is None

    def test_unknown_severity_degrades_to_medium(self) -> None:
        payload = {"id": "w", "name": "CVE-1", "severity": "SPICY", "serviceName": "api"}
        assert parse_webhook(payload).severity is Severity.MEDIUM

    def test_non_object_payload_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="must be a JSON object"):
            parse_webhook(["not", "an", "object"])  # type: ignore[arg-type]


class FakeStore:
    def __init__(self, allow: bool = True, reason: str = "") -> None:
        self.allow = allow
        self.reason = reason
        self.marks: list[tuple[str, RunStatus]] = []

    def should_process(self, finding: Finding) -> tuple[bool, str]:
        return self.allow, self.reason

    def mark(self, finding: Finding, status: RunStatus, **fields: Any) -> None:
        self.marks.append((finding.dedupe_key, status))

    def record_outcome(self, outcome: Any) -> None:
        self.marks.append((outcome.finding.dedupe_key, outcome.status))


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> TestClient:
    from sir_fix_a_bot.intake import app as app_module

    monkeypatch.setattr(app_module, "get_settings", lambda: settings)
    monkeypatch.setattr(app_module, "RunStore", lambda _s: FakeStore())
    monkeypatch.setattr(app_module, "_enqueue", lambda _s, _f: None)
    return TestClient(app)


class TestWebhookAuth:
    def test_missing_token_is_rejected(self, client: TestClient) -> None:
        response = client.post("/webhook/wiz", json=WIZ_PAYLOAD)
        assert response.status_code == 401

    def test_wrong_token_is_rejected(self, client: TestClient) -> None:
        response = client.post("/webhook/wiz", json=WIZ_PAYLOAD, headers={"x-sfb-token": "wrong"})
        assert response.status_code == 401

    def test_error_body_does_not_describe_the_check(self, client: TestClient) -> None:
        """A detailed message would help an attacker probe the comparison."""
        response = client.post("/webhook/wiz", json=WIZ_PAYLOAD, headers={"x-sfb-token": "x"})
        assert response.json()["detail"] == "unauthorized"

    def test_correct_token_is_accepted(self, client: TestClient) -> None:
        response = client.post(
            "/webhook/wiz", json=WIZ_PAYLOAD, headers={"x-sfb-token": "test-webhook-secret"}
        )
        assert response.status_code == 202


class TestWebhookFiltering:
    def test_finding_below_threshold_is_dropped(
        self, client: TestClient, settings: Settings
    ) -> None:
        settings.wiz_min_severity = "CRITICAL"
        payload = {
            "vulnerability": WIZ_PAYLOAD["vulnerability"] | {"severity": "MEDIUM"}  # type: ignore[operator]
        }
        response = client.post(
            "/webhook/wiz", json=payload, headers={"x-sfb-token": "test-webhook-secret"}
        )
        assert response.json()["status"] == "ignored"

    def test_duplicate_is_dropped(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sir_fix_a_bot.intake import app as app_module

        monkeypatch.setattr(
            app_module, "RunStore", lambda _s: FakeStore(allow=False, reason="already running")
        )
        response = client.post(
            "/webhook/wiz", json=WIZ_PAYLOAD, headers={"x-sfb-token": "test-webhook-secret"}
        )
        assert response.json() == {"status": "duplicate", "reason": "already running"}

    def test_malformed_payload_returns_400_not_500(self, client: TestClient) -> None:
        response = client.post(
            "/webhook/wiz", json={"nope": True}, headers={"x-sfb-token": "test-webhook-secret"}
        )
        assert response.status_code == 400


class TestDedupeWindows:
    """The suppression logic, exercised without Firestore."""

    def _store(self, settings: Settings, record: dict[str, Any] | None) -> RunStore:
        store = RunStore(settings)

        class Snapshot:
            exists = record is not None

            def to_dict(self) -> dict[str, Any] | None:
                return record

        class Doc:
            def get(self) -> Snapshot:
                return Snapshot()

        class Collection:
            def document(self, _key: str) -> Doc:
                return Doc()

        store._collection = lambda: Collection()  # type: ignore[method-assign]
        return store

    @pytest.fixture
    def finding(self) -> Finding:
        return Finding(id="w", name="CVE-1", service_name="api")

    def test_unseen_finding_is_processed(self, settings: Settings, finding: Finding) -> None:
        assert self._store(settings, None).should_process(finding)[0]

    def test_running_finding_is_suppressed(self, settings: Settings, finding: Finding) -> None:
        record = {"status": "running", "updated_at": datetime.now(UTC)}
        allowed, reason = self._store(settings, record).should_process(finding)
        assert not allowed
        assert "already running" in reason

    def test_stale_running_finding_is_retried(self, settings: Settings, finding: Finding) -> None:
        """A worker evicted mid-run must not wedge the finding forever."""
        record = {"status": "running", "updated_at": datetime.now(UTC) - timedelta(hours=2)}
        assert self._store(settings, record).should_process(finding)[0]

    def test_open_pr_suppresses_for_a_long_window(
        self, settings: Settings, finding: Finding
    ) -> None:
        """Wiz keeps re-firing while the PR is open; reopening it every scan would be noise."""
        record = {"status": "pr_open", "updated_at": datetime.now(UTC) - timedelta(days=3)}
        assert not self._store(settings, record).should_process(finding)[0]

    def test_open_pr_is_retried_after_the_window(
        self, settings: Settings, finding: Finding
    ) -> None:
        record = {"status": "pr_open", "updated_at": datetime.now(UTC) - timedelta(days=45)}
        assert self._store(settings, record).should_process(finding)[0]

    def test_failure_is_retried_sooner_than_a_block(
        self, settings: Settings, finding: Finding
    ) -> None:
        """A hard failure is often transient; a block is a human decision."""
        recent = datetime.now(UTC) - timedelta(hours=8)
        assert self._store(settings, {"status": "failed", "updated_at": recent}).should_process(
            finding
        )[0]
        assert not self._store(
            settings, {"status": "blocked", "updated_at": recent}
        ).should_process(finding)[0]

    def test_unknown_status_does_not_raise(self, settings: Settings, finding: Finding) -> None:
        record = {"status": "bananas", "updated_at": datetime.now(UTC)}
        assert isinstance(self._store(settings, record).should_process(finding)[0], bool)
