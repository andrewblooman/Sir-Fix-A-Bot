from __future__ import annotations

import pytest

from sir_fix_a_bot.agent.dockerfile import parse


class TestStageParsing:
    def test_single_stage(self) -> None:
        df = parse("FROM python:3.11-slim\nRUN pip install -r requirements.txt\n")

        assert not df.is_multistage
        assert df.stages[0].image == "python:3.11-slim"
        assert df.stages[0].image_name == "python"
        assert df.stages[0].tag == "3.11-slim"
        assert df.stages[0].version == (3, 11)

    def test_multistage_with_aliases(self) -> None:
        df = parse(
            "FROM python:3.11-slim AS builder\n"
            "RUN pip install --prefix=/install -r requirements.txt\n"
            "FROM python:3.11-slim\n"
            "COPY --from=builder /install /usr/local\n"
        )

        assert df.is_multistage
        assert df.stages[0].alias == "builder"
        assert df.stages[1].alias is None
        assert df.final_stage is df.stages[1]

    def test_platform_flag_is_ignored(self) -> None:
        df = parse("FROM --platform=linux/amd64 python:3.11-slim AS build\n")
        assert df.stages[0].image == "python:3.11-slim"
        assert df.stages[0].alias == "build"

    def test_comments_and_blank_lines_skipped(self) -> None:
        df = parse("# a comment\n\nFROM python:3.11-slim\n# another\nRUN echo hi\n")
        assert len(df.stages) == 1
        assert [i.keyword for i in df.stages[0].instructions] == ["RUN"]

    def test_line_continuations_are_joined(self) -> None:
        """A naive line-wise scan would see `apt-get install` as a separate instruction."""
        df = parse(
            "FROM python:3.11-slim\n"
            "RUN apt-get update \\\n"
            "    && apt-get install -y curl \\\n"
            "    && rm -rf /var/lib/apt/lists/*\n"
        )
        runs = df.instructions("RUN")
        assert len(runs) == 1
        assert "apt-get install -y curl" in runs[0].value

    def test_arg_before_first_from_does_not_create_a_stage(self) -> None:
        df = parse("ARG PY=3.11\nFROM python:3.11-slim\n")
        assert len(df.stages) == 1

    def test_unparseable_input_yields_no_stages(self) -> None:
        assert parse("").stages == []


class TestVersionExtraction:
    @pytest.mark.parametrize(
        ("image", "expected"),
        [
            ("python:3.11-slim", (3, 11)),
            ("python:3.11.14-slim", (3, 11)),
            ("python:3.12", (3, 12)),
            ("python:3", (3, None)),
            ("node:22-alpine", (22, None)),
            # The parser reports what the tag says; the gate decides how many components
            # matter for this image family (Node breaks on the major alone).
            ("node:22.3.1-bookworm-slim", (22, 3)),
            ("golang:1.22", (1, 22)),
            ("python:latest", None),
            ("gcr.io/distroless/python3-debian12", None),
            ("python", None),
        ],
    )
    def test_version_parsing(self, image: str, expected: tuple[int, int | None] | None) -> None:
        assert parse(f"FROM {image}\n").stages[0].version == expected

    def test_registry_port_is_not_mistaken_for_a_tag(self) -> None:
        stage = parse("FROM localhost:5000/myimage:1.2\n").stages[0]
        assert stage.image_name == "localhost:5000/myimage"
        assert stage.tag == "1.2"

    def test_digest_pinned_image(self) -> None:
        stage = parse("FROM python:3.11-slim@sha256:abc123\n").stages[0]
        assert stage.image_name == "python"
        assert stage.version == (3, 11)

    def test_templated_image_is_flagged(self) -> None:
        assert parse("FROM ${BASE_IMAGE}\n").stages[0].is_templated
        assert not parse("FROM python:3.11-slim\n").stages[0].is_templated


class TestLabelParsing:
    def test_multiline_label_block(self) -> None:
        df = parse(
            "FROM python:3.11-slim\n"
            'LABEL org.opencontainers.image.source="https://github.com/a/b" \\\n'
            '      org.opencontainers.image.title="svc" \\\n'
            '      org.opencontainers.image.revision="${BUILD_REVISION}"\n'
        )
        labels = df.labels(df.stages[0])

        assert labels["org.opencontainers.image.source"] == "https://github.com/a/b"
        assert labels["org.opencontainers.image.title"] == "svc"
        assert labels["org.opencontainers.image.revision"] == "${BUILD_REVISION}"

    def test_quoted_values_with_spaces(self) -> None:
        df = parse('FROM x\nLABEL org.opencontainers.image.description="A payments API"\n')
        assert df.labels(df.stages[0])["org.opencontainers.image.description"] == "A payments API"

    def test_multiple_label_instructions_merge(self) -> None:
        df = parse('FROM x\nLABEL a="1"\nLABEL b="2"\n')
        assert df.labels(df.stages[0]) == {"a": "1", "b": "2"}

    def test_labels_are_scoped_to_their_stage(self) -> None:
        """Labels on the builder stage do not end up on the shipped image."""
        df = parse('FROM x AS builder\nLABEL a="1"\nFROM y\nLABEL b="2"\n')
        assert df.labels(df.stages[0]) == {"a": "1"}
        assert df.labels(df.final_stage) == {"b": "2"}  # type: ignore[arg-type]

    def test_legacy_space_separated_form(self) -> None:
        df = parse("FROM x\nLABEL maintainer Jane Doe\n")
        assert df.labels(df.stages[0]) == {"maintainer": "Jane Doe"}
