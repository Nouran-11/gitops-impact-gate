from __future__ import annotations

import asyncio
import json
import logging

import httpx
import pytest

from impactgate.analysis.severity import raise_only
from impactgate.llm import BATCH_SIZE, FakeProvider, explain_findings, needs_llm, parse_verdicts
from impactgate.llm.provider import (
    FallbackProvider,
    PermanentError,
    RateLimitError,
    build_provider,
)
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


class _Boom:
    def __init__(self, name: str, error: Exception) -> None:
        self.name = name
        self.error = error
        self.calls = 0

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        del prompt, max_tokens
        self.calls += 1
        raise self.error


class _Ok:
    name = "groq"

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        del prompt, max_tokens
        self.calls += 1
        return '{"verdicts":[]}'


async def _no_sleep(_delay: float) -> None:
    return None


def test_missing_api_key_is_not_retried_and_logged_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("impactgate.llm.provider.asyncio.sleep", _no_sleep)
    caplog.set_level(logging.WARNING, logger="impactgate.llm")
    missing = _Boom("gemini", PermanentError("GEMINI_API_KEY is not set"))
    ok = _Ok()
    chain = FallbackProvider([missing, ok], max_attempts=3)
    asyncio.run(chain.complete("first"))
    asyncio.run(chain.complete("second"))
    assert missing.calls == 1
    assert ok.calls == 2
    assert sum("unavailable" in rec.message for rec in caplog.records) == 1


def test_rate_limit_retries_then_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("impactgate.llm.provider.asyncio.sleep", _no_sleep)
    limited = _Boom("gemini", RateLimitError(0))
    ok = _Ok()
    chain = FallbackProvider([limited, ok], max_attempts=3)
    asyncio.run(chain.complete("hi"))
    assert limited.calls == 3
    assert ok.calls == 1


def test_http_5xx_retries_then_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("impactgate.llm.provider.asyncio.sleep", _no_sleep)
    request = httpx.Request("POST", "https://example.test")
    response = httpx.Response(503, request=request)
    error = httpx.HTTPStatusError("server error", request=request, response=response)
    failing = _Boom("gemini", error)
    ok = _Ok()
    chain = FallbackProvider([failing, ok], max_attempts=3)
    asyncio.run(chain.complete("hi"))
    assert failing.calls == 3
    assert ok.calls == 1


def test_build_provider_wires_ollama_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IMPACTGATE_OLLAMA_MODEL", raising=False)
    chain = build_provider("ollama")
    assert isinstance(chain, FallbackProvider)
    assert chain.providers[0].name == "ollama"
    assert chain.providers[0].model == "llama3.1:8b"
    monkeypatch.setenv("IMPACTGATE_OLLAMA_MODEL", "mistral:7b")
    from_env = build_provider("ollama")
    assert from_env.providers[0].model == "mistral:7b"
    override = build_provider("ollama", ollama_model="qwen2.5:7b")
    assert override.providers[0].model == "qwen2.5:7b"


def test_group_packs_unique_rules_into_batches_of_ten() -> None:
    findings = [_numbered_finding(index) for index in range(40)]
    provider = FakeProvider()
    asyncio.run(explain_findings(findings, provider=provider))
    assert len(provider.calls) == 4
    assert BATCH_SIZE == 10


def test_scanner_finding_never_carries_graph_explanation() -> None:
    graph = _finding()
    scanner = Finding(
        id=compute_finding_id("KSV-0014", "_cluster/Kubernetes/deployment", "ro"),
        origin="scanner",
        rule="KSV-0014",
        resource=ResourceRef(api_version="v1", kind="Kubernetes", name="deployment"),
        path=["_cluster/Kubernetes/deployment"],
        evidence=(
            "deployment.yaml: Root file system is not read-only. "
            "Remediation: set readOnlyRootFilesystem."
        ),
        severity_floor=Severity.HIGH,
    )
    provider = FakeProvider()
    verdicts = asyncio.run(explain_findings([graph, scanner], provider=provider))
    assert needs_llm(scanner) is False
    assert len(provider.calls) == 1
    by_rule = {item.rule: item for item in verdicts}
    assert by_rule["KSV-0014"].explanation == scanner.evidence
    assert "selector matches no pods" not in by_rule["KSV-0014"].explanation
    assert by_rule["KSV-0014"].origin == "scanner"
    assert "broken-selector" in by_rule["broken-selector"].explanation


def test_style_scanner_findings_skip_llm() -> None:
    graph = _finding()
    scanner = Finding(
        id=compute_finding_id("unset-cpu-requirements", "demo/Deployment/checkout", "cpu"),
        origin="scanner",
        rule="unset-cpu-requirements",
        resource=ResourceRef(
            api_version="apps/v1", kind="Deployment", name="checkout", namespace="demo"
        ),
        path=["demo/Deployment/checkout"],
        evidence="deployment.yaml: container is missing cpu requests",
        severity_floor=Severity.LOW,
    )
    provider = FakeProvider()
    verdicts = asyncio.run(explain_findings([graph, scanner], provider=provider))
    assert needs_llm(graph) is True
    assert needs_llm(scanner) is False
    assert len(provider.calls) == 1
    assert verdicts[1].explanation == scanner.evidence
    assert verdicts[1].severity == Severity.LOW
    assert verdicts[0].severity == Severity.CRITICAL


def test_unmatched_finding_id_degrades_instead_of_attaching() -> None:
    first = _finding("broken-selector")
    second = _finding("unreachable-workload")
    payload = {
        "verdicts": [
            {
                "finding_id": None,
                "severity": "high",
                "explanation": "The same generic sentence for every finding.",
                "suggested_fix": None,
                "confidence": 0.9,
            }
        ]
    }
    provider = FakeProvider(responses=[json.dumps(payload)])
    verdicts = asyncio.run(explain_findings([first, second], provider=provider))
    assert all("unavailable" in item.explanation for item in verdicts)
    assert verdicts[0].finding_id == first.id
    assert verdicts[1].finding_id == second.id


def test_severity_floor_is_per_finding() -> None:
    graph = _finding()
    scanner = Finding(
        id="scanner-low",
        origin="scanner",
        rule="unset-cpu-requirements",
        resource=ResourceRef(
            api_version="apps/v1", kind="Deployment", name="checkout", namespace="demo"
        ),
        path=["demo/Deployment/checkout"],
        evidence="cpu requests missing",
        severity_floor=Severity.LOW,
    )
    provider = FakeProvider()
    verdicts = asyncio.run(explain_findings([graph, scanner], provider=provider))
    by_rule = {item.rule: item for item in verdicts}
    assert by_rule["broken-selector"].severity == Severity.CRITICAL
    assert by_rule["unset-cpu-requirements"].severity == Severity.LOW


def test_high_scanner_findings_skip_llm_and_keep_scanner_text() -> None:
    finding = Finding(
        id="scanner-high",
        origin="scanner",
        rule="CKV_K8S_30",
        resource=ResourceRef(
            api_version="apps/v1", kind="Deployment", name="checkout", namespace="demo"
        ),
        path=["demo/Deployment/checkout"],
        evidence="Guideline: set seccompProfile to RuntimeDefault",
        severity_floor=Severity.HIGH,
    )
    provider = FakeProvider(
        responses=[
            json.dumps(
                {
                    "verdicts": [
                        {
                            "finding_id": finding.id,
                            "severity": "high",
                            "explanation": (
                                "KSV-0014: the Service selector matches no pods, "
                                "so traffic through the Ingress stops reaching the workload."
                            ),
                            "suggested_fix": "seccompProfile:\n  type: Unconfined",
                            "confidence": 0.99,
                        }
                    ]
                }
            )
        ]
    )
    verdicts = asyncio.run(explain_findings([finding], provider=provider))
    assert provider.calls == []
    assert verdicts[0].suggested_fix is None
    assert verdicts[0].explanation == finding.evidence
    assert "selector matches no pods" not in verdicts[0].explanation


def test_low_confidence_graph_patch_is_dropped() -> None:
    finding = _finding()
    payload = {
        "verdicts": [
            {
                "finding_id": finding.id,
                "severity": "critical",
                "explanation": "Traffic will miss the pods.",
                "suggested_fix": "spec:\n  selector:\n    app: checkout",
                "confidence": 0.2,
            }
        ]
    }
    provider = FakeProvider(responses=[json.dumps(payload)])
    verdicts = asyncio.run(explain_findings([finding], provider=provider))
    assert verdicts[0].suggested_fix is None
    assert verdicts[0].explanation == "Traffic will miss the pods."


def test_prompt_forbids_insecure_scanner_patches() -> None:
    from impactgate.llm.prompts import PROMPT_TEMPLATE

    assert "wrong patch is worse than no patch" in PROMPT_TEMPLATE
    assert "scanners ship their own remediation" in PROMPT_TEMPLATE
    assert "seccompProfile: unconfined" in PROMPT_TEMPLATE


def _numbered_finding(index: int) -> Finding:
    ref = ResourceRef(api_version="v1", kind="Service", name=f"svc-{index}", namespace="demo")
    evidence = f"finding {index}"
    return Finding(
        id=compute_finding_id(f"rule-{index}", ref.key(), evidence),
        origin="graph",
        rule=f"rule-{index}",
        resource=ref,
        path=[ref.key()],
        evidence=evidence,
        severity_floor=Severity.MEDIUM,
    )
