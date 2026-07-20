# Intake service: verify, normalise, dedupe, enqueue. No agent, no git, no Node.
#
# This follows the same house rules the bot enforces on everyone else — multi-stage, pinned to a
# patch version, OCI labels with build-arg provenance, and deliberately no USER directive (identity
# is set at deploy time by the Cloud Run service account).

FROM python:3.14.4-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --prefix=/install .

FROM python:3.14.4-slim

ARG BUILD_REVISION=unknown
ARG BUILD_CREATED=unknown
LABEL org.opencontainers.image.source="https://github.com/andrewblooman/Sir-Fix-A-Bot" \
      org.opencontainers.image.url="https://github.com/andrewblooman/Sir-Fix-A-Bot" \
      org.opencontainers.image.title="sir-fix-a-bot-intake" \
      org.opencontainers.image.description="Receives Wiz vulnerability webhooks, deduplicates findings and enqueues remediation work" \
      org.opencontainers.image.vendor="andrewblooman" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${BUILD_REVISION}" \
      org.opencontainers.image.version="${BUILD_REVISION}" \
      org.opencontainers.image.created="${BUILD_CREATED}"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

COPY --from=builder /install /usr/local

EXPOSE 8080
CMD ["sh", "-c", "exec uvicorn sir_fix_a_bot.intake.app:app --host 0.0.0.0 --port ${PORT}"]
