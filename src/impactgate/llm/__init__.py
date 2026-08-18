"""LLM explanation layer. Findings are computed elsewhere; this layer only explains them."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence

from impactgate.analysis.severity import raise_only
from impactgate.cache.store import CacheStore
from impactgate.llm.prompts import PROMPT_VERSION, STRICT_RETRY, render_prompt
from impactgate.llm.provider import FakeProvider, Provider, ProviderError, build_provider
from impactgate.llm.schema import ModelBatch, ModelVerdict
from impactgate.models import Finding, Verdict

LOGGER = logging.getLogger("impactgate.llm")
BATCH_SIZE = 10
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
    for finding in findings:
        hit = cache.get_verdict(finding.id) if cache is not None else None
        if hit is not None:
            if cache is not None:
                cache.stats.llm_calls_saved += 1
            cached_verdicts[finding.id] = hit
        else:
            pending.append(finding)
    fresh: list[Verdict] = []
    grouped = _group(pending)
    for batch in grouped:
        if cache is not None:
            cache.stats.llm_calls_made += 1
        fresh.extend(
            await _explain_batch(batch, active, diffs=diffs, environment=environment)
        )
    if cache is not None:
        for verdict in fresh:
            cache.put_verdict(verdict)
    by_id = {**cached_verdicts, **{item.finding_id: item for item in fresh}}
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
        result.append(
            Verdict(
                finding_id=finding.id,
                severity=raise_only(finding.severity_floor, match.severity),
                explanation=match.explanation,
                suggested_fix=match.suggested_fix,
                confidence=match.confidence,
            )
        )
    return result


def _take_match(remaining: list[ModelVerdict], finding_id: str) -> ModelVerdict | None:
    for index, item in enumerate(remaining):
        if item.finding_id == finding_id:
            return remaining.pop(index)
    for index, item in enumerate(remaining):
        if item.finding_id in {None, ""}:
            return remaining.pop(index)
    return None


def _degraded(finding: Finding) -> Verdict:
    return Verdict(
        finding_id=finding.id,
        severity=finding.severity_floor,
        explanation=DEGRADED_EXPLANATION,
        suggested_fix=None,
        confidence=0.0,
    )


def _group(findings: Sequence[Finding]) -> list[list[Finding]]:
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(finding)
    batches: list[list[Finding]] = []
    for group in by_rule.values():
        for start in range(0, len(group), BATCH_SIZE):
            batches.append(group[start : start + BATCH_SIZE])
    return batches


__all__ = [
    "BATCH_SIZE",
    "DEGRADED_EXPLANATION",
    "FakeProvider",
    "PROMPT_VERSION",
    "Provider",
    "build_provider",
    "explain_findings",
    "parse_verdicts",
]
