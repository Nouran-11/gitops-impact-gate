"""On-disk cache."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from impactgate.cache.fingerprint import content_hash
from impactgate.graph.parser import ParseError, ParseResult, parse_file
from impactgate.models import Finding, Resource, Verdict

LOGGER = logging.getLogger("impactgate.cache")


@dataclass
class CacheStats:
    nodes_evaluated: int = 0
    nodes_reused: int = 0
    llm_calls_made: int = 0
    llm_calls_saved: int = 0
    uncacheable: bool = False

    def render(self) -> str:
        return "\n".join(
            [
                "## Cache",
                "",
                f"- nodes evaluated: {self.nodes_evaluated}",
                f"- nodes reused: {self.nodes_reused}",
                f"- LLM calls made: {self.llm_calls_made}",
                f"- LLM calls saved: {self.llm_calls_saved}",
                "",
            ]
        )


@dataclass
class CacheStore:
    root: Path
    enabled: bool = True
    stats: CacheStats = field(default_factory=CacheStats)

    def __post_init__(self) -> None:
        if self.enabled:
            self.root.mkdir(parents=True, exist_ok=True)

    def get_json(self, tier: str, key: str) -> Any | None:
        if not self.enabled or self.stats.uncacheable:
            return None
        path = self._path(tier, key)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            LOGGER.warning("ignoring corrupt cache file %s", path)
            return None

    def put_json(self, tier: str, key: str, value: Any) -> None:
        if not self.enabled or self.stats.uncacheable:
            return
        path = self._path(tier, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    def parse_file(self, path: Path, *, source_file: str) -> ParseResult:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            return ParseResult(errors=[ParseError(source_file=source_file, message=str(exc))])
        key = content_hash(text)
        cached = self.get_json("parse", key)
        if cached is not None:
            self.stats.nodes_reused += 1
            return _parse_result_from_json(cached)
        result = parse_file(path, source_file=source_file)
        self.stats.nodes_evaluated += 1
        if result.ok:
            self.put_json("parse", key, _parse_result_to_json(result))
        return result

    def get_scanner_findings(self, file_hash: str, scanner: str) -> list[Finding] | None:
        cached = self.get_json("scanner", content_hash(f"{file_hash}:{scanner}"))
        if cached is None:
            return None
        return [Finding.model_validate(item) for item in cached]

    def put_scanner_findings(self, file_hash: str, scanner: str, findings: list[Finding]) -> None:
        self.put_json(
            "scanner",
            content_hash(f"{file_hash}:{scanner}"),
            [item.model_dump(mode="json") for item in findings],
        )

    def get_verdict(self, finding_id: str) -> Verdict | None:
        cached = self.get_json("llm", finding_id)
        if cached is None:
            return None
        try:
            return Verdict.model_validate(cached)
        except Exception:
            return None

    def put_verdict(self, verdict: Verdict) -> None:
        if verdict.confidence <= 0.0:
            return
        self.put_json("llm", verdict.finding_id, verdict.model_dump(mode="json"))

    def _path(self, tier: str, key: str) -> Path:
        return self.root / tier / f"{key}.json"


def parse_directory_cached(root: Path, cache: CacheStore) -> ParseResult:
    from impactgate.graph.parser import SKIP_FILENAMES, YAML_SUFFIXES, ParseError, ParseResult

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
        file_result = cache.parse_file(path, source_file=relative)
        result.resources.extend(file_result.resources)
        result.errors.extend(file_result.errors)
    return result


def _parse_result_to_json(result: ParseResult) -> dict[str, Any]:
    return {
        "resources": [item.model_dump(mode="json") for item in result.resources],
        "errors": [
            {
                "source_file": item.source_file,
                "message": item.message,
                "source_line": item.source_line,
            }
            for item in result.errors
        ],
    }


def _parse_result_from_json(payload: Any) -> ParseResult:
    if not isinstance(payload, dict):
        return ParseResult()
    resources = [Resource.model_validate(item) for item in payload.get("resources") or []]
    errors = [
        ParseError(
            source_file=str(item.get("source_file", "")),
            message=str(item.get("message", "")),
            source_line=item.get("source_line"),
        )
        for item in payload.get("errors") or []
        if isinstance(item, dict)
    ]
    return ParseResult(resources=resources, errors=errors)
