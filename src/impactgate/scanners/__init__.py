"""Deterministic scanners for known rule violations."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path

from impactgate.models import Finding
from impactgate.scanners.base import Scanner
from impactgate.scanners.checkov import CheckovScanner
from impactgate.scanners.kubelinter import KubeLinterScanner
from impactgate.scanners.trivy import TrivyScanner

LOGGER = logging.getLogger("impactgate.scanners")


async def run_all_scanners(files: Sequence[Path]) -> list[Finding]:
    """Run Checkov, Trivy, and kube-linter concurrently over ``files``."""
    if not files:
        return []
    scanners: tuple[Scanner, ...] = (CheckovScanner(), TrivyScanner(), KubeLinterScanner())
    results = await asyncio.gather(*(_safe_scan(scanner, files) for scanner in scanners))
    findings: list[Finding] = []
    for result in results:
        findings.extend(result)
    return deduplicate(findings)


async def _safe_scan(scanner: Scanner, files: Sequence[Path]) -> list[Finding]:
    try:
        return await scanner.scan(files)
    except Exception as exc:
        LOGGER.warning("%s failed: %s", scanner.name, exc)
        return []


def deduplicate(findings: Sequence[Finding]) -> list[Finding]:
    """Keep one finding per (rule, resource key)."""
    unique: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.rule, finding.resource.key())
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
