"""Resolve a Cloud Run service to its GitHub repo via the Notion CMDB, over MCP.

Notion's *hosted* MCP server (`mcp.notion.com/mcp`) is OAuth-browser-only and explicitly not built
for headless agents, so we self-host `@notionhq/notion-mcp-server` over stdio with an internal
integration token instead.

This lookup runs in the orchestrator, deterministically, rather than being left to the agent. A
wrong answer here means opening a pull request against someone else's repository, so the resolver
fails loudly on a missing or ambiguous row and never falls back to fuzzy matching.

Note the Notion API's 2025-09-03 data-source model: a database contains one or more *data sources*,
and rows are queried from the data source, not the database. We resolve the database id to its data
source id once per process.
"""

from __future__ import annotations

import json
import logging
import os
import re
from contextlib import AsyncExitStack
from typing import Any, Self

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sir_fix_a_bot.config import Settings, resolve_secret
from sir_fix_a_bot.models import ServiceRecord

logger = logging.getLogger(__name__)

_REPO_URL = re.compile(r"github\.com[:/]+(?P<owner>[^/]+)/(?P<name>[^/#?.]+)", re.IGNORECASE)


class CmdbLookupError(RuntimeError):
    """The CMDB could not answer authoritatively for this service."""


class NotionCmdb:
    """Reads the CMDB database through a self-hosted Notion MCP server on stdio."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stack = AsyncExitStack()
        self._session: ClientSession | None = None
        self._data_source_id: str | None = None

    async def __aenter__(self) -> Self:
        env = {
            # The MCP server is a Node process; it needs PATH and friends, but must not inherit
            # any of our other credentials.
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108
            "NOTION_TOKEN": resolve_secret(self._settings.notion_token),
        }
        params = StdioServerParameters(
            command=self._settings.notion_mcp_command,
            args=self._settings.notion_mcp_args,
            env=env,
        )
        read, write = await self._stack.enter_async_context(stdio_client(params))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        self._session = session
        logger.info("Notion MCP session initialised")
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()
        self._session = None

    # --- MCP plumbing -----------------------------------------------------------------

    async def _call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Invoke an MCP tool and decode its JSON payload."""
        if self._session is None:
            raise CmdbLookupError("Notion MCP session is not open")

        result = await self._session.call_tool(tool, arguments)
        if result.isError:
            raise CmdbLookupError(f"Notion MCP tool {tool} failed: {_text_of(result.content)}")

        text = _text_of(result.content)
        if not text:
            raise CmdbLookupError(f"Notion MCP tool {tool} returned no content")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CmdbLookupError(f"Notion MCP tool {tool} returned non-JSON content") from exc
        if not isinstance(payload, dict):
            raise CmdbLookupError(f"Notion MCP tool {tool} returned {type(payload).__name__}")
        return payload

    async def _resolve_data_source_id(self) -> str:
        """Map the configured database id to its data source id (Notion API 2025-09-03)."""
        if self._data_source_id:
            return self._data_source_id

        database = await self._call(
            "API-retrieve-a-database",
            {"database_id": self._settings.notion_cmdb_database_id},
        )
        sources = database.get("data_sources") or []
        if not sources:
            raise CmdbLookupError(
                f"CMDB database {self._settings.notion_cmdb_database_id} exposes no data sources; "
                "check the integration has been shared with the page"
            )
        if len(sources) > 1:
            names = ", ".join(str(s.get("name")) for s in sources)
            logger.warning(
                "CMDB database has %d data sources (%s); using the first", len(sources), names
            )

        self._data_source_id = str(sources[0]["id"])
        return self._data_source_id

    # --- lookup -----------------------------------------------------------------------

    async def resolve(self, service_name: str) -> ServiceRecord:
        """Return the CMDB record for `service_name`.

        Raises `CmdbLookupError` when there is no row or more than one, rather than guessing.
        """
        data_source_id = await self._resolve_data_source_id()
        prop = self._settings.notion_prop_service

        response = await self._call(
            "API-query-data-source",
            {
                "data_source_id": data_source_id,
                "filter": {"property": prop, "title": {"equals": service_name}},
                "page_size": 5,
            },
        )
        rows = response.get("results") or []

        if not rows:
            raise CmdbLookupError(
                f"No CMDB row for Cloud Run service {service_name!r}. Add it to the CMDB "
                "(or correct the service name) before this finding can be remediated."
            )
        if len(rows) > 1:
            urls = ", ".join(str(r.get("url")) for r in rows)
            raise CmdbLookupError(
                f"CMDB has {len(rows)} rows for service {service_name!r} ({urls}). "
                "Refusing to guess which repository owns it."
            )

        return self._to_record(service_name, rows[0])

    def _to_record(self, service_name: str, row: dict[str, Any]) -> ServiceRecord:
        props = row.get("properties") or {}
        s = self._settings

        repo_url = _prop_text(props.get(s.notion_prop_repo))
        if not repo_url:
            raise CmdbLookupError(
                f"CMDB row for {service_name!r} has no value in the {s.notion_prop_repo!r} column"
            )

        match = _REPO_URL.search(repo_url)
        if not match:
            raise CmdbLookupError(
                f"CMDB repo value for {service_name!r} is not a GitHub URL: {repo_url!r}"
            )
        full_name = f"{match['owner']}/{match['name']}"

        return ServiceRecord(
            service_name=service_name,
            repo_url=f"https://github.com/{full_name}",  # type: ignore[arg-type]
            repo_full_name=full_name,
            default_branch=_prop_text(props.get(s.notion_prop_branch)) or "main",
            owner=_prop_text(props.get(s.notion_prop_owner)) or None,
            team=_prop_text(props.get(s.notion_prop_team)) or None,
            dockerfile_path=_prop_text(props.get(s.notion_prop_dockerfile)) or "Dockerfile",
            notion_page_url=row.get("url"),
        )


def _text_of(content: Any) -> str:
    """Concatenate the text parts of an MCP tool result's content blocks."""
    parts: list[str] = []
    for block in content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def _prop_text(prop: Any) -> str:
    """Flatten a Notion property value to plain text.

    Notion returns a differently-shaped object per property type, and CMDB columns are frequently
    retyped by hand (a URL column becomes rich text, an owner becomes a select), so every common
    shape is handled rather than assuming one.
    """
    if not isinstance(prop, dict):
        return ""

    match prop.get("type"):
        case "title" | "rich_text" as kind:
            return "".join(part.get("plain_text", "") for part in prop.get(kind) or []).strip()
        case "url":
            return str(prop.get("url") or "").strip()
        case "email":
            return str(prop.get("email") or "").strip()
        case "select":
            return str((prop.get("select") or {}).get("name") or "").strip()
        case "multi_select":
            return ", ".join(o.get("name", "") for o in prop.get("multi_select") or []).strip()
        case "people":
            return ", ".join(p.get("name", "") for p in prop.get("people") or []).strip()
        case "formula":
            formula = prop.get("formula") or {}
            return str(formula.get("string") or formula.get("number") or "").strip()
        case "rollup":
            rollup = prop.get("rollup") or {}
            return ", ".join(_prop_text(item) for item in rollup.get("array") or []).strip(", ")
        case _:
            return ""
