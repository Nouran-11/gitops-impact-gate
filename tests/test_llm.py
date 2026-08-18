from __future__ import annotations

import asyncio
import json

from impactgate.analysis.severity import raise_only
from impactgate.llm import FakeProvider, explain_findings, parse_verdicts
from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id


def _finding(rule: str = "broken-selector", severity: Severity = Severity.CRITICAL) -> Finding:
    ref = ResourceRef(api_version="v1", kind="Service", name="checkout", namespace="demo")
    evidence = "spec.selector app=checkout matches no workload"
    return Finding(
        id=compute_finding_id(rule, ref.key(), evidence),
        origin="graph",
        rule=rule,
        resource=ref,
        path=["demo/Ingress/public", ref.key(), "(no pods)"],
        evidence=evidence,
        severity_floor=severity,
    )


def test_parse_strips_markdown_fences() -> None:
    raw = """```json
{"severity":"high","explanation":"Traffic will miss the pods.",
 "suggested_fix":null,"confidence":0.8}
```"""
    parsed = parse_verdicts(raw)
    assert parsed is not None
    assert parsed[0].severity == Severity.HIGH
    assert "Traffic will miss" in parsed[0].explanation


def test_llm_may_raise_but_not_lower_severity() -> None:
    assert raise_only(Severity.CRITICAL, Severity.LOW) == Severity.CRITICAL
    assert raise_only(Severity.MEDIUM, Severity.HIGH) == Severity.HIGH


def test_fake_provider_explains_without_network() -> None:
    finding = _finding()
    provider = FakeProvider()
    verdicts = asyncio.run(explain_findings([finding], provider=provider))
    assert len(verdicts) == 1
    assert verdicts[0].finding_id == finding.id
    assert verdicts[0].confidence > 0
    assert "broken-selector" in verdicts[0].explanation
    assert verdicts[0].severity == Severity.CRITICAL
    assert provider.calls


def test_invalid_json_retries_then_degrades() -> None:
    finding = _finding()
    provider = FakeProvider(responses=["not-json", "still-not-json"])
    verdicts = asyncio.run(explain_findings([finding], provider=provider))
    assert verdicts[0].confidence == 0.0
    assert "unavailable" in verdicts[0].explanation
    assert len(provider.calls) == 2


def test_batch_returns_one_verdict_per_finding() -> None:
    findings = [_finding("broken-selector"), _finding("unreachable-workload")]
    payload = {
        "verdicts": [
            {
                "finding_id": findings[0].id,
                "severity": "critical",
                "explanation": "The Ingress still points at a Service with no pods.",
                "suggested_fix": None,
                "confidence": 0.95,
            },
            {
                "finding_id": findings[1].id,
                "severity": "high",
                "explanation": "The Deployment is no longer selected by any Service.",
                "suggested_fix": None,
                "confidence": 0.9,
            },
        ]
    }
    provider = FakeProvider(responses=[json.dumps(payload)])
    verdicts = asyncio.run(explain_findings(findings, provider=provider))
    assert [item.finding_id for item in verdicts] == [item.id for item in findings]
    assert "Ingress" in verdicts[0].explanation
