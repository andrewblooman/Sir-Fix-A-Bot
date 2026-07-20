"""A small Dockerfile parser, sufficient for the gate's checks.

Deliberately not a full implementation — it needs to answer three questions accurately: which base
images are used and at what version, whether a `USER` instruction is present, and which labels the
final stage carries. Line continuations and comments are handled because real Dockerfiles use them
heavily and a naive line-wise scan misreads them.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

#: `python:3.11.14-slim` -> ("3", "11"). Also matches a bare `3.11` and `1.22-alpine`.
_VERSION = re.compile(r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?")


@dataclass(frozen=True)
class Instruction:
    keyword: str
    value: str
    #: 1-based line number of the instruction's first physical line.
    line: int


@dataclass
class Stage:
    """One `FROM ... [AS name]` block."""

    image: str
    alias: str | None
    line: int
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def image_name(self) -> str:
        """Registry path without the tag or digest, e.g. `python`, `gcr.io/distroless/static`."""
        ref = self.image.split("@", 1)[0]
        # A colon before the last slash is a registry port, not a tag.
        head, _, tail = ref.rpartition(":")
        if head and "/" not in tail:
            return head
        return ref

    @property
    def tag(self) -> str | None:
        ref = self.image.split("@", 1)[0]
        head, sep, tail = ref.rpartition(":")
        if sep and head and "/" not in tail:
            return tail
        return None

    @property
    def version(self) -> tuple[int, int | None] | None:
        """Parsed `(major, minor)` from the tag, or None when the tag carries no version.

        `python:3.11-slim` -> (3, 11); `python:latest` and `distroless/static:nonroot` -> None.
        """
        if not self.tag:
            return None
        match = _VERSION.match(self.tag)
        if not match:
            return None
        minor = match["minor"]
        return int(match["major"]), int(minor) if minor is not None else None

    @property
    def is_templated(self) -> bool:
        """True when the base image comes from a build ARG, so its version cannot be read here."""
        return "$" in self.image


@dataclass
class Dockerfile:
    stages: list[Stage]

    @property
    def is_multistage(self) -> bool:
        return len(self.stages) > 1

    @property
    def final_stage(self) -> Stage | None:
        return self.stages[-1] if self.stages else None

    def instructions(self, keyword: str) -> list[Instruction]:
        """Every instruction of `keyword` across all stages."""
        return [
            instruction
            for stage in self.stages
            for instruction in stage.instructions
            if instruction.keyword == keyword
        ]

    def labels(self, stage: Stage) -> dict[str, str]:
        """Flatten every `LABEL` in `stage` into a single mapping."""
        result: dict[str, str] = {}
        for instruction in stage.instructions:
            if instruction.keyword == "LABEL":
                result |= _parse_label(instruction.value)
        return result


def parse(text: str) -> Dockerfile:
    """Parse `text` into stages.

    Unparseable input yields an empty stage list rather than raising.
    """
    stages: list[Stage] = []
    preamble: list[Instruction] = []

    for keyword, value, line in _logical_lines(text):
        if keyword == "FROM":
            image, alias = _parse_from(value)
            stages.append(Stage(image=image, alias=alias, line=line))
        elif stages:
            stages[-1].instructions.append(Instruction(keyword, value, line))
        else:
            # ARG before the first FROM is legal and common.
            preamble.append(Instruction(keyword, value, line))

    return Dockerfile(stages=stages)


def _logical_lines(text: str) -> list[tuple[str, str, int]]:
    """Join continuations and strip comments, yielding `(KEYWORD, value, line_number)`."""
    out: list[tuple[str, str, int]] = []
    buffer = ""
    start_line = 0

    for index, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start_line = index

        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue

        buffer += stripped
        keyword, _, value = buffer.strip().partition(" ")
        if keyword:
            out.append((keyword.upper(), value.strip(), start_line))
        buffer = ""

    if buffer.strip():
        keyword, _, value = buffer.strip().partition(" ")
        if keyword:
            out.append((keyword.upper(), value.strip(), start_line))
    return out


def _parse_from(value: str) -> tuple[str, str | None]:
    """Split a FROM value into image and alias, dropping flags like `--platform=`."""
    tokens = [t for t in value.split() if not t.startswith("--")]
    if not tokens:
        return "", None
    image = tokens[0]
    alias = None
    if len(tokens) >= 3 and tokens[1].upper() == "AS":
        alias = tokens[2]
    return image, alias


def _parse_label(value: str) -> dict[str, str]:
    """Parse `LABEL k=v k2="v 2"` and the legacy `LABEL key value` form."""
    try:
        tokens = shlex.split(value)
    except ValueError:
        tokens = value.split()

    if tokens and "=" not in tokens[0]:
        # Legacy single-label form: LABEL maintainer Jane Doe
        return {tokens[0]: " ".join(tokens[1:]).strip('"')}

    result: dict[str, str] = {}
    for token in tokens:
        key, sep, val = token.partition("=")
        if sep:
            result[key.strip()] = val.strip().strip('"')
    return result
