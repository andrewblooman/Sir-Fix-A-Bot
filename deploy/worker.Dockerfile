# Worker service: runs the agent, so it needs git and Node in addition to Python.
#
# Node is here because the Notion CMDB lookup goes through `@notionhq/notion-mcp-server`, which is
# a Node process. Notion's hosted MCP server is OAuth-browser-only and cannot be used headless.
#
# The MCP server is npm-installed and version-pinned at build time rather than fetched with
# `npx -y` at runtime: a network fetch on every remediation run is slow, unpinned, and a supply
# chain risk on a service that holds a GitHub App key.
#
# There is deliberately no gcloud SDK — the verification build is submitted through the Cloud Build
# API client, which avoids ~1GB of image for a single API call.
#
# Follows the same house rules the bot enforces: multi-stage, pinned patch version, OCI labels with
# build-arg provenance, no USER directive.

FROM python:3.14.4-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --prefix=/install .

FROM node:22-slim AS mcp

# Pinned deliberately. Renovate/Dependabot should bump this like any other dependency.
ARG NOTION_MCP_VERSION=1.9.0
RUN npm install --global --prefix /mcp "@notionhq/notion-mcp-server@${NOTION_MCP_VERSION}"

FROM python:3.14.4-slim

ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
LABEL org.opencontainers.image.source="https://github.com/andrewblooman/Sir-Fix-A-Bot" \
      org.opencontainers.image.url="https://github.com/andrewblooman/Sir-Fix-A-Bot" \
      org.opencontainers.image.title="sir-fix-a-bot-worker" \
      org.opencontainers.image.description="Resolves a Wiz finding to its repository, produces a verified fix with a coding agent and opens a pull request" \
      org.opencontainers.image.vendor="andrewblooman" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.version="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_CREATED}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    PATH="/usr/local/bin:/mcp/bin:${PATH}" \
    NODE_PATH=/mcp/lib/node_modules \
    SFB_NOTION_MCP_COMMAND=notion-mcp-server \
    SFB_NOTION_MCP_ARGS='["--transport","stdio"]' \
    SFB_WORKTREE_ROOT=/tmp/sfb-worktrees

# git for cloning target repositories; ca-certificates for TLS to GitHub, Wiz and Notion.
# --no-install-recommends keeps the surface (and the finding count) down.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY --from=mcp /usr/local/bin/node /usr/local/bin/node
COPY --from=mcp /mcp /mcp

EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn sir_fix_a_bot.intake.app:app --host 0.0.0.0 --port ${PORT}"]
