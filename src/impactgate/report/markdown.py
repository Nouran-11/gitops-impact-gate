"""PR comment rendering."""

from __future__ import annotations

from impactgate.models import GateDecision, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def render_report(decision: GateDecision) -> str:
    """Render a GateDecision as a Markdown report."""
    lines = [
        "# Impact Gate",
        "",
        f"**Risk:** {decision.risk}",
        "",
        decision.reason,
        "",
    ]
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
