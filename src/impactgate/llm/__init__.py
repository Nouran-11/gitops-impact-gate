"""LLM explanation layer. Findings are computed elsewhere; this layer only explains them."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence

from impactgate.analysis.severity import accepted_suggested_fix, raise_only
from impactgate.cache.store import CacheStore
from impactgate.llm.prompts import STRICT_RETRY, render_prompt
from impactgate.llm.provider import (
    FakeProvider,
    PermanentError,
    Provider,
    ProviderError,
    build_provider,
)
from impactgate.llm.schema import ModelBatch, ModelVerdict
from impactgate.metrics import REGISTRY
from impactgate.models import Finding, Severity, Verdict
from impactgate.prompting import PROMPT_VERSION

LOGGER = logging.getLogger("impactgate.llm")
BATCH_SIZE = 10
SCANNER_LLM_MIN_SEVERITY = Severity.HIGH
DEGRADED_EXPLANATION = (
    "Analysis was unavailable; the deterministic finding is shown without an LLM explanation."
)

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)


async def explain_findings(
    findings: Sequence[Finding],
    *,
    provider: Provider | None = None,
    diffs: str = "(none)",
    environment: str = "namespace unknown, exposure unknown",
    cache: CacheStore | None = None,
) -> list[Verdict]:
    """Explain findings in batches. Never raises; degrades on provider/parse failure."""
    if not findings:
        return []
    active = provider if provider is not None else build_provider()
    cached_verdicts: dict[str, Verdict] = {}
    pending: list[Finding] = []
    verbatim: dict[str, Verdict] = {}
    for finding in findings:
        if not needs_llm(finding):
            verbatim[finding.id] = _verbatim_verdict(finding)
            continue
        hit = cache.get_verdict(finding.id) if cache is not None else None
        if hit is not None:
            if cache is not None:
                cache.stats.llm_calls_saved += 1
            REGISTRY.record_llm(getattr(active, "name", "unknown"), cached=True)
            cached_verdicts[finding.id] = _with_finding_meta(hit, finding)
        else:
            pending.append(finding)
    fresh: list[Verdict] = []
    grouped = _group(pending)
    for batch in grouped:
        if cache is not None:
            cache.stats.llm_calls_made += 1
        REGISTRY.record_llm(getattr(active, "name", "unknown"), cached=False)
        fresh.extend(
            await _explain_batch(batch, active, diffs=diffs, environment=environment)
        )
    if cache is not None:
        for verdict in fresh:
            cache.put_verdict(verdict)
    by_id = {**verbatim, **cached_verdicts, **{item.finding_id: item for item in fresh}}
    ordered: list[Verdict] = []
    for finding in findings:
        if finding.id in by_id:
            ordered.append(by_id[finding.id])
        else:
            ordered.append(_degraded(finding))
    return ordered


async def _explain_batch(
    findings: Sequence[Finding],
    provider: Provider,
    *,
    diffs: str,
    environment: str,
) -> list[Verdict]:
    prompt = render_prompt(findings, diffs=diffs, environment=environment)
    raw = await _complete(provider, prompt)
    parsed = parse_verdicts(raw) if raw is not None else None
    if parsed is None:
        retry_prompt = f"{prompt}\n\n{STRICT_RETRY}"
        raw = await _complete(provider, retry_prompt)
        parsed = parse_verdicts(raw) if raw is not None else None
    if parsed is None:
        return [_degraded(finding) for finding in findings]
    return _match_verdicts(findings, parsed)


async def _complete(provider: Provider, prompt: str) -> str | None:
    try:
        return await provider.complete(prompt)
    except ProviderError:
        LOGGER.warning("provider failed; using degraded verdicts")
        return None
    except Exception:
        LOGGER.exception("provider raised; using degraded verdicts")
        return None


def parse_verdicts(raw: str) -> list[ModelVerdict] | None:
    stripped = _FENCE.sub("", raw.strip()).strip()
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, list):
        try:
            return [ModelVerdict.model_validate(item) for item in payload]
        except Exception:
            return None
    if isinstance(payload, dict) and "verdicts" in payload:
        try:
            return ModelBatch.model_validate(payload).verdicts
        except Exception:
            return None
    if isinstance(payload, dict):
        try:
            return [ModelVerdict.model_validate(payload)]
        except Exception:
            return None
    return None


def _match_verdicts(findings: Sequence[Finding], parsed: Sequence[ModelVerdict]) -> list[Verdict]:
    remaining = list(parsed)
    result: list[Verdict] = []
    for finding in findings:
        match = _take_match(remaining, finding.id)
        if match is None:
            result.append(_degraded(finding))
            continue
        explanation = match.explanation
        if finding.origin == "scanner" and finding.evidence and finding.evidence not in explanation:
            explanation = f"{explanation}\n\n{finding.evidence}"
        result.append(
            _verdict(
                finding,
                severity=raise_only(finding.severity_floor, match.severity),
                explanation=explanation,
                suggested_fix=accepted_suggested_fix(
                    finding.origin, match.suggested_fix, match.confidence
                ),
                confidence=match.confidence,
            )
        )
    return result


def _take_match(remaining: list[ModelVerdict], finding_id: str) -> ModelVerdict | None:
    for index, item in enumerate(remaining):
        if item.finding_id == finding_id:
            return remaining.pop(index)
    return None


def _degraded(finding: Finding) -> Verdict:
    return _verdict(
        finding,
        severity=finding.severity_floor,
        explanation=DEGRADED_EXPLANATION,
        suggested_fix=None,
        confidence=0.0,
    )


def _verbatim_verdict(finding: Finding) -> Verdict:
    return _verdict(
        finding,
        severity=finding.severity_floor,
        explanation=finding.evidence,
        suggested_fix=None,
        confidence=1.0,
    )


def _verdict(
    finding: Finding,
    *,
    severity: Severity,
    explanation: str,
    suggested_fix: str | None,
    confidence: float,
) -> Verdict:
    return Verdict(
        finding_id=finding.id,
        severity=severity,
        explanation=explanation,
        suggested_fix=suggested_fix,
        confidence=confidence,
        origin=finding.origin,
        path=list(finding.path),
        rule=finding.rule,
    )


def _with_finding_meta(verdict: Verdict, finding: Finding) -> Verdict:
    return verdict.model_copy(
        update={
            "origin": finding.origin,
            "path": list(finding.path),
            "rule": finding.rule,
            "suggested_fix": accepted_suggested_fix(
                finding.origin, verdict.suggested_fix, verdict.confidence
            ),
        }
    )


def needs_llm(finding: Finding) -> bool:
    """Graph findings always; scanner findings only at or above the severity threshold."""
    if finding.origin == "graph":
        return True
    return _severity_rank(finding.severity_floor) >= _severity_rank(SCANNER_LLM_MIN_SEVERITY)


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }[severity]


def _group(findings: Sequence[Finding]) -> list[list[Finding]]:
    """Keep same-rule findings together, then pack into batches of BATCH_SIZE."""
    by_rule: dict[str, list[Finding]] = {}
    order: list[str] = []
    for finding in findings:
        if finding.rule not in by_rule:
            order.append(finding.rule)
            by_rule[finding.rule] = []
        by_rule[finding.rule].append(finding)
    packed: list[Finding] = []
    for rule in order:
        packed.extend(by_rule[rule])
    return [packed[start : start + BATCH_SIZE] for start in range(0, len(packed), BATCH_SIZE)]


__all__ = [
    "BATCH_SIZE",
    "DEGRADED_EXPLANATION",
    "SCANNER_LLM_MIN_SEVERITY",
    "FakeProvider",
    "PermanentError",
    "PROMPT_VERSION",
    "Provider",
    "build_provider",
    "explain_findings",
    "needs_llm",
    "parse_verdicts",
]
