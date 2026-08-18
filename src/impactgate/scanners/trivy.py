"""Trivy scanner wrapper."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id
from impactgate.scanners.base import run_command

LOGGER = logging.getLogger("impactgate.scanners.trivy")


class TrivyScanner:
    name = "trivy"

    async def scan(self, files: Sequence[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            raw = await run_command("trivy", ["config", str(path), "--format", "json"])
            if not raw:
                continue
            findings.extend(parse_trivy_json(raw, path))
        return findings


def parse_trivy_json(raw: str, source: Path) -> list[Finding]:
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError:
        LOGGER.warning("trivy returned invalid JSON for %s", source)
        return []
    results = payload.get("Results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return []
    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        misconfigs = result.get("Misconfigurations") or result.get("Misconfs") or []
        if not isinstance(misconfigs, list):
            continue
        for item in misconfigs:
            if not isinstance(item, dict):
                continue
            finding = _finding_from_misconfig(item, source)
            if finding is not None:
                findings.append(finding)
    return findings


def _finding_from_misconfig(item: dict[str, Any], source: Path) -> Finding | None:
    rule = item.get("ID") or item.get("AVDID")
    if not isinstance(rule, str) or not rule:
        return None
    title = item.get("Title")
    evidence = title if isinstance(title, str) else rule
    ref = ResourceRef(api_version="v1", kind="File", name=source.name)
    cause = item.get("CauseMetadata")
    if isinstance(cause, dict):
        kind = cause.get("Resource") or cause.get("Provider")
        if isinstance(kind, str) and kind:
            ref = ResourceRef(api_version="v1", kind=kind, name=source.stem)
    return Finding(
        id=compute_finding_id(rule, ref.key(), evidence),
        origin="scanner",
        rule=rule,
        resource=ref,
        path=[ref.key()],
        evidence=f"{source.name}: {evidence}",
        severity_floor=_severity(item.get("Severity")),
    )


def _severity(value: object) -> Severity:
    if not isinstance(value, str):
        return Severity.MEDIUM
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(value.upper(), Severity.MEDIUM)
