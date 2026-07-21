from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from sir_fix_a_bot import config
from sir_fix_a_bot.config import (
    SecretResolutionError,
    _SecretCache,
    clear_secret_cache,
    resolve_secret,
)

RESOURCE = "projects/p/secrets/sfb-notion-token/versions/latest"


@pytest.fixture(autouse=True)
def _clean_cache() -> Any:
    clear_secret_cache()
    yield
    clear_secret_cache()


class TestLiteralVsReference:
    def test_literal_value_is_returned_unchanged(self) -> None:
        """Local development sets real values directly; no GCP call should happen."""
        assert resolve_secret(SecretStr("ntn_local_dev_token")) == "ntn_local_dev_token"

    @pytest.mark.parametrize(
        "value",
        [
            "ntn_abc123",
            "sk-ant-abc",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "projects/p/secrets/name",  # incomplete — not a version reference
            "projects/p/secrets/name/versions",  # incomplete
        ],
    )
    def test_non_reference_shapes_are_treated_as_literals(self, value: str) -> None:
        assert resolve_secret(SecretStr(value)) == value

    def test_reference_is_fetched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(config, "_fetch_secret_version", lambda _r: "fetched-value")
        assert resolve_secret(SecretStr(RESOURCE)) == "fetched-value"

    @pytest.mark.parametrize(
        "resource",
        [
            "projects/p/secrets/s/versions/latest",
            "projects/my-project-123/secrets/sfb-wiz-client-id/versions/4",
        ],
    )
    def test_reference_shapes_are_recognised(
        self, resource: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "_fetch_secret_version", lambda _r: "v")
        assert resolve_secret(SecretStr(resource)) == "v"


class TestCaching:
    def test_repeated_reads_hit_secret_manager_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = []
        monkeypatch.setattr(config, "_fetch_secret_version", lambda r: calls.append(r) or "value")

        for _ in range(5):
            resolve_secret(SecretStr(RESOURCE))

        assert len(calls) == 1

    def test_rotation_is_picked_up_after_the_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unbounded cache would keep a rotated credential alive for the life of the instance,
        which is exactly wrong when the reason for rotating was a compromise."""
        values = iter(["old-secret", "new-secret"])
        cache = _SecretCache(ttl_seconds=0)
        monkeypatch.setattr(config, "_fetch_secret_version", lambda _r: next(values))
        monkeypatch.setattr(config, "_secret_cache", cache)

        assert resolve_secret(SecretStr(RESOURCE)) == "old-secret"
        assert resolve_secret(SecretStr(RESOURCE)) == "new-secret"

    def test_value_is_held_within_the_ttl(self, monkeypatch: pytest.MonkeyPatch) -> None:
        values = iter(["first", "second"])
        cache = _SecretCache(ttl_seconds=3600)
        monkeypatch.setattr(config, "_fetch_secret_version", lambda _r: next(values))
        monkeypatch.setattr(config, "_secret_cache", cache)

        assert resolve_secret(SecretStr(RESOURCE)) == "first"
        assert resolve_secret(SecretStr(RESOURCE)) == "first"

    def test_distinct_resources_are_cached_separately(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(config, "_fetch_secret_version", lambda r: f"value-for-{r[-1]}")

        a = resolve_secret(SecretStr("projects/p/secrets/a/versions/1"))
        b = resolve_secret(SecretStr("projects/p/secrets/b/versions/2"))

        assert a != b

    def test_clear_forces_a_refetch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = []
        monkeypatch.setattr(config, "_fetch_secret_version", lambda r: calls.append(r) or "value")

        resolve_secret(SecretStr(RESOURCE))
        clear_secret_cache()
        resolve_secret(SecretStr(RESOURCE))

        assert len(calls) == 2


class TestErrorHandling:
    def test_permission_denied_names_the_role_to_grant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from google.api_core import exceptions as gcp_exceptions

        monkeypatch.setattr(
            "google.cloud.secretmanager.SecretManagerServiceClient",
            lambda *a, **k: (_ for _ in ()).throw(gcp_exceptions.PermissionDenied("nope")),
        )

        with pytest.raises(SecretResolutionError) as exc:
            resolve_secret(SecretStr(RESOURCE))

        assert "secretmanager.secretAccessor" in str(exc.value)

    def test_missing_secret_says_how_to_create_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from google.api_core import exceptions as gcp_exceptions

        monkeypatch.setattr(
            "google.cloud.secretmanager.SecretManagerServiceClient",
            lambda *a, **k: (_ for _ in ()).throw(gcp_exceptions.NotFound("gone")),
        )

        with pytest.raises(SecretResolutionError, match="gcloud secrets versions add"):
            resolve_secret(SecretStr(RESOURCE))

    def test_secret_value_is_not_echoed_in_the_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from google.api_core import exceptions as gcp_exceptions

        monkeypatch.setattr(
            "google.cloud.secretmanager.SecretManagerServiceClient",
            lambda *a, **k: (_ for _ in ()).throw(
                gcp_exceptions.InternalServerError("upstream said ntn_leaked_value")
            ),
        )

        with pytest.raises(SecretResolutionError) as exc:
            resolve_secret(SecretStr(RESOURCE))

        assert "ntn_leaked_value" not in str(exc.value)


class TestPayloadHandling:
    def test_trailing_newline_is_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`echo value | gcloud secrets versions add --data-file=-` appends a newline, and it is
        the most common reason a correctly-stored secret fails to authenticate."""

        class Payload:
            data = b"ntn_abc123\n"

        class Response:
            payload = Payload()

        class Client:
            def access_secret_version(self, request: dict[str, Any]) -> Response:
                return Response()

        monkeypatch.setattr(
            "google.cloud.secretmanager.SecretManagerServiceClient", lambda *a, **k: Client()
        )

        assert resolve_secret(SecretStr(RESOURCE)) == "ntn_abc123"

    def test_multiline_pem_survives_intact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A GitHub App key is a multi-line PEM; stripping must not touch the interior newlines."""
        pem = "-----BEGIN RSA PRIVATE KEY-----\nline1\nline2\n-----END RSA PRIVATE KEY-----\n"

        class Payload:
            data = pem.encode()

        class Response:
            payload = Payload()

        class Client:
            def access_secret_version(self, request: dict[str, Any]) -> Response:
                return Response()

        monkeypatch.setattr(
            "google.cloud.secretmanager.SecretManagerServiceClient", lambda *a, **k: Client()
        )

        resolved = resolve_secret(SecretStr(RESOURCE))
        assert resolved == pem.strip()
        assert resolved.count("\n") == 3
        assert resolved.startswith("-----BEGIN")
        assert resolved.endswith("-----END RSA PRIVATE KEY-----")
