"""Prompt templates, versioned."""

from __future__ import annotations

from collections.abc import Sequence

from impactgate.models import Finding
from impactgate.prompting import PROMPT_VERSION

PROMPT_TEMPLATE = """You explain Kubernetes graph/scanner findings that are already verified.
Do not look for new problems. Do not invent issues. Ranking and a patch are your only jobs.

Return ONLY JSON: an object with key "verdicts" whose value is an array of objects:
{{
  "verdicts": [
    {{
      "finding_id": "string",
      "severity": "critical|high|medium|low",
      "explanation": "2-3 sentences, plain English, no jargon",
      "suggested_fix": "unified diff or null",
      "confidence": 0.0
    }}
  ]
}}

suggested_fix rules (a wrong patch is worse than no patch):
- Graph findings only. For scanner findings, always null — scanners ship their own remediation.
- Return a unified diff only when you are highly confident it is correct.
- Never weaken security: no seccompProfile: unconfined, no allowPrivilegeEscalation: true,
  no privileged ports (0-1023) described as non-privileged, no runAsUser: 0.
- If unsure, set suggested_fix to null rather than guessing.

You may raise severity above the floor. You may not lower it; the caller enforces that.

Findings:
{findings}

Diff hunks (never the whole file):
{diffs}

Environment: {environment}
"""

STRICT_RETRY = (
    "Your previous reply was not valid JSON. Reply with only the JSON object described, "
    "no markdown fences, no commentary."
)


def render_prompt(
    findings: Sequence[Finding],
    *,
    diffs: str = "(none)",
    environment: str = "namespace unknown, exposure unknown",
) -> str:
    rendered = []
    for finding in findings:
        rendered.append(
            "\n".join(
                [
                    f"- finding_id: {finding.id}",
                    f"  rule: {finding.rule}",
                    f"  resource: {finding.resource.key()}",
                    f"  evidence: {finding.evidence}",
                    f"  path: {' -> '.join(finding.path)}",
                    f"  severity_floor: {finding.severity_floor.value}",
                ]
            )
        )
    return PROMPT_TEMPLATE.format(
        findings="\n".join(rendered) or "(none)",
        diffs=diffs,
        environment=environment,
    )


__all__ = ["PROMPT_TEMPLATE", "PROMPT_VERSION", "STRICT_RETRY", "render_prompt"]
