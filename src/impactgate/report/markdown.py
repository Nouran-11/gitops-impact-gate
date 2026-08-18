"""PR comment rendering."""

from __future__ import annotations

from collections.abc import Sequence

from impactgate.models import GateDecision, Severity
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
    diagram = from_paths(paths or _paths_from_verdicts(decision))
    lines.extend(["## Impact graph", "", "```mermaid", diagram, "```", ""])
    if not decision.verdicts:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    ordered = sorted(decision.verdicts, key=lambda v: _SEVERITY_ORDER[v.severity])
    lines.append("## Findings")
    lines.append("")
    for verdict in ordered:
        lines.append(f"### {verdict.severity.value}: `{verdict.finding_id}`")
        lines.append("")
        lines.append(verdict.explanation)
        lines.append("")
        if verdict.suggested_fix:
            lines.append("```suggestion")
            lines.append(verdict.suggested_fix)
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def _paths_from_verdicts(decision: GateDecision) -> list[list[str]]:
    paths: list[list[str]] = []
    for verdict in decision.verdicts:
        marker = "Path: "
        if marker in verdict.explanation:
            rendered = verdict.explanation.split(marker, 1)[-1].rstrip(".")
            paths.append([part.strip() for part in rendered.replace("→", "->").split("->")])
    return paths
