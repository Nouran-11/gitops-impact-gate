"""Deterministic scanners for known rule violations."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path

from impactgate.cache.fingerprint import content_hash
from impactgate.cache.store import CacheStore
from impactgate.models import Finding
from impactgate.scanners.base import Scanner
from impactgate.scanners.checkov import CheckovScanner
from impactgate.scanners.kubelinter import KubeLinterScanner
from impactgate.scanners.trivy import TrivyScanner

LOGGER = logging.getLogger("impactgate.scanners")


async def run_all_scanners(
    files: Sequence[Path],
    *,
    cache: CacheStore | None = None,
) -> list[Finding]:
    """Run Checkov, Trivy, and kube-linter concurrently over ``files``."""
    if not files:
        return []
    scanners: tuple[Scanner, ...] = (CheckovScanner(), TrivyScanner(), KubeLinterScanner())
    results = await asyncio.gather(
        *(_safe_scan(scanner, files, cache=cache) for scanner in scanners)
    )
    findings: list[Finding] = []
    for result in results:
        findings.extend(result)
    return deduplicate(findings)


async def _safe_scan(
    scanner: Scanner,
    files: Sequence[Path],
    *,
    cache: CacheStore | None = None,
) -> list[Finding]:
    bundle = _bundle_key(scanner.name, files)
    if cache is not None:
        hit = cache.get_scanner_findings(bundle, scanner.name)
        if hit is not None:
            return hit
    try:
        findings = await scanner.scan(files)
    except Exception as exc:
        LOGGER.warning("%s failed: %s", scanner.name, exc)
        return []
    if cache is not None:
        cache.put_scanner_findings(bundle, scanner.name, findings)
    return findings


def _bundle_key(scanner: str, files: Sequence[Path]) -> str:
    parts = [scanner]
    for path in files:
        if path.is_file():
            parts.append(content_hash(path.read_bytes()))
        else:
            parts.append(path.name)
    return content_hash(":".join(parts))


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
