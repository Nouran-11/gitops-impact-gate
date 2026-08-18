"""PR comment rendering."""

from __future__ import annotations

from collections.abc import Sequence

from impactgate.analysis.severity import accepted_suggested_fix
from impactgate.cache.store import CacheStats
from impactgate.models import GateDecision, Severity, Verdict
from impactgate.report.mermaid import from_paths

COMMENT_MARKER = "<!-- impact-gate -->"

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_STATUS = {"low": "success", "medium": "neutral", "high": "failure"}


def status_for_risk(risk: str) -> str:
    return _STATUS.get(risk, "failure")


def render_report(
    decision: GateDecision,
    *,
    paths: Sequence[Sequence[str]] | None = None,
    cache_stats: CacheStats | None = None,
) -> str:
    """Render a GateDecision as a Markdown PR comment."""
    lines = [
        COMMENT_MARKER,
        "# Impact Gate",
        "",
        f"**Risk:** {decision.risk}",
        "",
        decision.reason,
        "",
    ]
    graph_verdicts = [item for item in decision.verdicts if item.origin == "graph"]
    scanner_verdicts = [item for item in decision.verdicts if item.origin == "scanner"]
    if paths is not None:
        diagram_paths = [list(path) for path in paths]
    else:
        diagram_paths = [item.path for item in graph_verdicts if item.path]
    if not diagram_paths:
        diagram_paths = _paths_from_verdicts(graph_verdicts)
    diagram = from_paths(diagram_paths)
    if diagram:
        lines.extend(["## Impact graph", "", "```mermaid", diagram, "```", ""])
    if not decision.verdicts:
        lines.append("No findings.")
        lines.append("")
        if cache_stats is not None:
            lines.append(cache_stats.render())
        return "\n".join(lines)

    if graph_verdicts:
        lines.append("## Relationship findings")
        lines.append("")
        _append_verdicts(lines, graph_verdicts)
    if scanner_verdicts:
        lines.append("## Scanner findings")
        lines.append("")
        _append_verdicts(lines, scanner_verdicts)
    if cache_stats is not None:
        lines.append(cache_stats.render())
    return "\n".join(lines)


def _append_verdicts(lines: list[str], verdicts: Sequence[Verdict]) -> None:
    ordered = sorted(verdicts, key=lambda item: (_SEVERITY_ORDER[item.severity], item.rule))
    for verdict in ordered:
        title = verdict.rule or verdict.finding_id
        lines.append(f"### {verdict.severity.value}: `{title}`")
        lines.append("")
        lines.append(verdict.explanation)
        lines.append("")
        patch = accepted_suggested_fix(verdict.origin, verdict.suggested_fix, verdict.confidence)
        if patch is not None:
            lines.append("```suggestion")
            lines.append(patch)
            lines.append("```")
            lines.append("")


def _paths_from_verdicts(verdicts: Sequence[Verdict]) -> list[list[str]]:
    paths: list[list[str]] = []
    for verdict in verdicts:
        if verdict.path:
            paths.append(list(verdict.path))
            continue
        marker = "Path: "
        if marker in verdict.explanation:
            rendered = verdict.explanation.split(marker, 1)[-1].rstrip(".")
            paths.append([part.strip() for part in rendered.replace("→", "->").split("->")])
    return paths
