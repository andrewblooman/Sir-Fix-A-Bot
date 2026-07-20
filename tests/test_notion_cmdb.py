from __future__ import annotations

import json
from typing import Any

import pytest

from sir_fix_a_bot.config import Settings
from sir_fix_a_bot.notion.cmdb import CmdbLookupError, NotionCmdb, _prop_text


def title(value: str) -> dict[str, Any]:
    return {"type": "title", "title": [{"plain_text": value}]}


def rich_text(value: str) -> dict[str, Any]:
    return {"type": "rich_text", "rich_text": [{"plain_text": value}]}


def url(value: str) -> dict[str, Any]:
    return {"type": "url", "url": value}


def row(**props: Any) -> dict[str, Any]:
    return {"url": "https://notion.so/page-1", "properties": props}


CMDB_ROW = row(
    **{
        "Service Name": title("checkout-api"),
        "GitHub Repo": url("https://github.com/acme/checkout-api"),
        "Owner": rich_text("Platform Team"),
        "Team": {"type": "select", "select": {"name": "payments"}},
        "Default Branch": rich_text("develop"),
        "Dockerfile Path": rich_text("services/api/Dockerfile"),
    }
)


class FakeCmdb(NotionCmdb):
    """NotionCmdb with the MCP transport replaced by canned responses."""

    def __init__(self, settings: Settings, rows: list[dict[str, Any]]) -> None:
        super().__init__(settings)
        self._rows = rows
        self._session = object()  # type: ignore[assignment]  # only truthiness is checked
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def _call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, arguments))
        if tool == "API-retrieve-a-database":
            return {"data_sources": [{"id": "ds-1", "name": "CMDB"}]}
        if tool == "API-query-data-source":
            return {"results": self._rows}
        raise AssertionError(f"unexpected tool {tool}")


class TestResolve:
    async def test_maps_row_to_service_record(self, settings: Settings) -> None:
        record = await FakeCmdb(settings, [CMDB_ROW]).resolve("checkout-api")

        assert record.repo_full_name == "acme/checkout-api"
        assert str(record.repo_url) == "https://github.com/acme/checkout-api"
        assert record.default_branch == "develop"
        assert record.owner == "Platform Team"
        assert record.team == "payments"
        assert record.dockerfile_path == "services/api/Dockerfile"

    async def test_defaults_applied_for_absent_optional_columns(self, settings: Settings) -> None:
        sparse = row(
            **{
                "Service Name": title("bare-svc"),
                "GitHub Repo": url("https://github.com/acme/bare-svc"),
            }
        )
        record = await FakeCmdb(settings, [sparse]).resolve("bare-svc")

        assert record.default_branch == "main"
        assert record.dockerfile_path == "Dockerfile"
        assert record.owner is None

    async def test_missing_row_raises_rather_than_guessing(self, settings: Settings) -> None:
        with pytest.raises(CmdbLookupError, match="No CMDB row"):
            await FakeCmdb(settings, []).resolve("ghost-svc")

    async def test_ambiguous_rows_raise_rather_than_picking_first(self, settings: Settings) -> None:
        """Two rows means we do not know which repo owns the service. Guessing would open a PR
        against the wrong codebase, so this must fail loudly."""
        with pytest.raises(CmdbLookupError, match="Refusing to guess"):
            await FakeCmdb(settings, [CMDB_ROW, CMDB_ROW]).resolve("checkout-api")

    async def test_row_without_repo_column_raises(self, settings: Settings) -> None:
        bad = row(**{"Service Name": title("no-repo")})
        with pytest.raises(CmdbLookupError, match="no value in the 'GitHub Repo' column"):
            await FakeCmdb(settings, [bad]).resolve("no-repo")

    async def test_non_github_repo_value_raises(self, settings: Settings) -> None:
        bad = row(
            **{
                "Service Name": title("gl-svc"),
                "GitHub Repo": url("https://gitlab.com/acme/gl-svc"),
            }
        )
        with pytest.raises(CmdbLookupError, match="not a GitHub URL"):
            await FakeCmdb(settings, [bad]).resolve("gl-svc")

    @pytest.mark.parametrize(
        "repo_value",
        [
            "https://github.com/acme/checkout-api",
            "https://github.com/acme/checkout-api.git",
            "git@github.com:acme/checkout-api.git",
            "https://github.com/acme/checkout-api/tree/main",
        ],
    )
    async def test_repo_url_forms_normalise_to_full_name(
        self, settings: Settings, repo_value: str
    ) -> None:
        """CMDB columns are hand-maintained, so clone URLs and tree links both turn up."""
        r = row(
            **{
                "Service Name": title("checkout-api"),
                "GitHub Repo": rich_text(repo_value),
            }
        )
        record = await FakeCmdb(settings, [r]).resolve("checkout-api")
        assert record.repo_full_name == "acme/checkout-api"

    async def test_data_source_resolved_once_and_reused(self, settings: Settings) -> None:
        cmdb = FakeCmdb(settings, [CMDB_ROW])
        await cmdb.resolve("checkout-api")
        await cmdb.resolve("checkout-api")

        retrievals = [c for c in cmdb.calls if c[0] == "API-retrieve-a-database"]
        assert len(retrievals) == 1

    async def test_query_filters_on_configured_title_property(self, settings: Settings) -> None:
        cmdb = FakeCmdb(settings, [CMDB_ROW])
        await cmdb.resolve("checkout-api")

        _, args = next(c for c in cmdb.calls if c[0] == "API-query-data-source")
        assert args["data_source_id"] == "ds-1"
        assert args["filter"] == {"property": "Service Name", "title": {"equals": "checkout-api"}}


class TestPropText:
    @pytest.mark.parametrize(
        ("prop", "expected"),
        [
            (title("a"), "a"),
            (rich_text(" padded "), "padded"),
            (url("https://x"), "https://x"),
            ({"type": "email", "email": "a@b.c"}, "a@b.c"),
            ({"type": "select", "select": {"name": "team-a"}}, "team-a"),
            ({"type": "select", "select": None}, ""),
            (
                {"type": "multi_select", "multi_select": [{"name": "x"}, {"name": "y"}]},
                "x, y",
            ),
            ({"type": "people", "people": [{"name": "Ada"}]}, "Ada"),
            ({"type": "formula", "formula": {"type": "string", "string": "f"}}, "f"),
            ({"type": "checkbox", "checkbox": True}, ""),
            (None, ""),
            ("not-a-dict", ""),
        ],
    )
    def test_flattens_each_notion_property_shape(self, prop: Any, expected: str) -> None:
        assert _prop_text(prop) == expected


class TestCallDecoding:
    async def test_non_json_tool_output_raises(self, settings: Settings) -> None:
        class Broken(NotionCmdb):
            async def _call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
                return json.loads("{}")

        # A well-formed but empty database response must still fail loudly.
        with pytest.raises(CmdbLookupError, match="no data sources"):
            await Broken(settings)._resolve_data_source_id()
