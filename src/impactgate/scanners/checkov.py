"""Checkov scanner wrapper."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id
from impactgate.scanners.base import run_command, with_guidance

LOGGER = logging.getLogger("impactgate.scanners.checkov")


class CheckovScanner:
    name = "checkov"

    async def scan(self, files: Sequence[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            raw = await run_command("checkov", ["-f", str(path), "-o", "json", "--compact"])
            if not raw:
                continue
            findings.extend(parse_checkov_json(raw, path))
        return findings


def parse_checkov_json(raw: str, source: Path) -> list[Finding]:
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError:
        LOGGER.warning("checkov returned invalid JSON for %s", source)
        return []
    documents = payload if isinstance(payload, list) else [payload]
    findings: list[Finding] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        results = document.get("results")
        if not isinstance(results, dict):
            continue
        failed = results.get("failed_checks")
        if not isinstance(failed, list):
            continue
        for check in failed:
            if not isinstance(check, dict):
                continue
            finding = _finding_from_check(check, source)
            if finding is not None:
                findings.append(finding)
    return findings


def _finding_from_check(check: dict[str, Any], source: Path) -> Finding | None:
    rule = check.get("check_id")
    if not isinstance(rule, str) or not rule:
        return None
    name = check.get("check_name")
    evidence = name if isinstance(name, str) else rule
    guideline = check.get("guideline")
    if isinstance(guideline, str) and guideline.strip():
        evidence = with_guidance(evidence, f"Guideline: {guideline.strip()}")
    resource_id = check.get("resource")
    ref = _ref_from_checkov_resource(resource_id if isinstance(resource_id, str) else None, source)
    return Finding(
        id=compute_finding_id(rule, ref.key(), evidence),
        origin="scanner",
        rule=rule,
        resource=ref,
        path=[ref.key()],
        evidence=f"{source.name}: {evidence}",
        severity_floor=_severity(check.get("severity")),
    )


def _ref_from_checkov_resource(resource_id: str | None, source: Path) -> ResourceRef:
    if not resource_id:
        return ResourceRef(api_version="v1", kind="File", name=source.name)
    if "/" not in resource_id and "." in resource_id:
        parts = resource_id.split(".")
        if len(parts) >= 3:
            kind, namespace, name = parts[0], parts[1], ".".join(parts[2:])
            return ResourceRef(api_version="v1", kind=kind, name=name, namespace=namespace)
        if len(parts) == 2:
            return ResourceRef(api_version="v1", kind=parts[0], name=parts[1])
    parts = [part for part in resource_id.replace(":", "/").split("/") if part]
    if len(parts) >= 2:
        return ResourceRef(
            api_version="v1",
            kind=parts[-2],
            name=parts[-1],
            namespace=parts[-3] if len(parts) >= 3 else None,
        )
    return ResourceRef(api_version="v1", kind="File", name=source.name)


def _severity(value: object) -> Severity:
    if not isinstance(value, str):
        return Severity.LOW
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.LOW,
        "UNKNOWN": Severity.LOW,
    }
    return mapping.get(value.upper(), Severity.LOW)
