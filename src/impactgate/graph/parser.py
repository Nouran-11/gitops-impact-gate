"""YAML -> Resource objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from impactgate.models import Resource, ResourceRef

YAML_SUFFIXES = {".yaml", ".yml"}
SKIP_FILENAMES = {".impactgate.yaml"}


@dataclass(frozen=True)
class ParseError:
    source_file: str
    message: str
    source_line: int | None = None


@dataclass
class ParseResult:
    resources: list[Resource] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def parse_directory(root: Path) -> ParseResult:
    """Parse every YAML file under ``root``. Unreadable documents become errors."""
    result = ParseResult()
    if not root.is_dir():
        result.errors.append(ParseError(source_file=str(root), message="not a directory"))
        return result
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in YAML_SUFFIXES:
            continue
        if path.name in SKIP_FILENAMES:
            continue
        relative = path.relative_to(root).as_posix()
        file_result = parse_file(path, source_file=relative)
        result.resources.extend(file_result.resources)
        result.errors.extend(file_result.errors)
    return result


def parse_file(path: Path, *, source_file: str | None = None) -> ParseResult:
    relative = source_file if source_file is not None else path.name
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ParseResult(errors=[ParseError(source_file=relative, message=str(exc))])
    return parse_text(text, source_file=relative)


def parse_text(text: str, *, source_file: str) -> ParseResult:
    result = ParseResult()
    for start_line, document_text in _split_documents(text):
        try:
            loaded = yaml.safe_load(document_text)
        except yaml.YAMLError as exc:
            result.errors.append(
                ParseError(
                    source_file=source_file,
                    source_line=start_line,
                    message=f"YAML parse error: {exc}",
                )
            )
            continue
        if loaded is None:
            continue
        resource, error = _resource_from_document(loaded, source_file, start_line)
        if error is not None:
            result.errors.append(error)
            continue
        if resource is not None:
            result.resources.append(resource)
    return result


def _split_documents(text: str) -> list[tuple[int, str]]:
    """Return (1-based start line, document text) pairs, skipping empty docs."""
    if not text.strip():
        return []
    lines = text.splitlines(keepends=True)
    documents: list[tuple[int, str]] = []
    current_start = 1
    current: list[str] = []
    started = False

    def flush() -> None:
        nonlocal current
        chunk = "".join(current)
        if chunk.strip() and chunk.strip() not in {"---", "..."}:
            documents.append((current_start, chunk))
        current = []

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped == "---" or stripped.startswith("--- "):
            if started:
                flush()
            current_start = index
            current = [line]
            started = True
            continue
        if not started:
            current_start = index
            started = True
        current.append(line)
    if started:
        flush()
    return documents


def _resource_from_document(
    loaded: object,
    source_file: str,
    source_line: int,
) -> tuple[Resource | None, ParseError | None]:
    if not isinstance(loaded, dict):
        return (
            None,
            ParseError(
                source_file=source_file,
                source_line=source_line,
                message="document is not a YAML mapping",
            ),
        )
    doc: dict[str, Any] = loaded
    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    name = metadata.get("name")
    if not isinstance(api_version, str) or not api_version:
        return (
            None,
            ParseError(
                source_file=source_file,
                source_line=source_line,
                message="missing apiVersion",
            ),
        )
    if not isinstance(kind, str) or not kind:
        return (
            None,
            ParseError(
                source_file=source_file,
                source_line=source_line,
                message="missing kind",
            ),
        )
    if not isinstance(name, str) or not name:
        return (
            None,
            ParseError(
                source_file=source_file,
                source_line=source_line,
                message="missing metadata.name",
            ),
        )
    namespace = metadata.get("namespace")
    if namespace is not None and not isinstance(namespace, str):
        return (
            None,
            ParseError(
                source_file=source_file,
                source_line=source_line,
                message="metadata.namespace must be a string",
            ),
        )
    resource = Resource(
        ref=ResourceRef(
            api_version=api_version,
            kind=kind,
            name=name,
            namespace=namespace,
        ),
        spec=doc,
        source_file=source_file,
        source_line=source_line,
    )
    return resource, None
