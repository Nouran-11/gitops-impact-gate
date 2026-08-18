"""kube-linter scanner wrapper."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id
from impactgate.scanners.base import run_command

LOGGER = logging.getLogger("impactgate.scanners.kubelinter")


class KubeLinterScanner:
    name = "kube-linter"

    async def scan(self, files: Sequence[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for path in files:
            raw = await run_command("kube-linter", ["lint", str(path), "--format", "json"])
            if not raw:
                continue
            findings.extend(parse_kubelinter_json(raw, path))
        return findings


def parse_kubelinter_json(raw: str, source: Path) -> list[Finding]:
    try:
        payload: Any = json.loads(raw)
    except json.JSONDecodeError:
        LOGGER.warning("kube-linter returned invalid JSON for %s", source)
        return []
    reports = payload.get("Reports") if isinstance(payload, dict) else None
    if reports is None and isinstance(payload, list):
        reports = payload
    if not isinstance(reports, list):
        return []
    findings: list[Finding] = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        finding = _finding_from_report(report, source)
        if finding is not None:
            findings.append(finding)
    return findings


def _finding_from_report(report: dict[str, Any], source: Path) -> Finding | None:
    rule = report.get("Check")
    if not isinstance(rule, str) or not rule:
        return None
    diagnostic = report.get("Diagnostic")
    message = ""
    if isinstance(diagnostic, dict) and isinstance(diagnostic.get("Message"), str):
        message = diagnostic["Message"]
    elif isinstance(report.get("Message"), str):
        message = report["Message"]
    evidence = message or rule
    ref = _ref_from_object(report.get("Object"), source)
    return Finding(
        id=compute_finding_id(rule, ref.key(), evidence),
        origin="scanner",
        rule=rule,
        resource=ref,
        path=[ref.key()],
        evidence=f"{source.name}: {evidence}",
        severity_floor=Severity.MEDIUM,
    )


def _ref_from_object(obj: object, source: Path) -> ResourceRef:
    if not isinstance(obj, dict):
        return ResourceRef(api_version="v1", kind="File", name=source.name)
    k8s = obj.get("K8sObject") if "K8sObject" in obj else obj
    if not isinstance(k8s, dict):
        return ResourceRef(api_version="v1", kind="File", name=source.name)
    kind = k8s.get("Kind") or "File"
    name = k8s.get("Name") or source.stem
    namespace = k8s.get("Namespace")
    if not isinstance(kind, str):
        kind = "File"
    if not isinstance(name, str):
        name = source.stem
    if namespace is not None and not isinstance(namespace, str):
        namespace = None
    return ResourceRef(api_version="v1", kind=kind, name=name, namespace=namespace)
