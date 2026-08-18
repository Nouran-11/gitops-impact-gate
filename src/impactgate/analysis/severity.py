"""Deterministic severity floor. The LLM may raise severity, never lower it."""

from __future__ import annotations

from impactgate.models import Severity

_SECRET_OR_CONFIG = {"Secret", "ConfigMap"}


def severity_floor(
    rule: str,
    *,
    externally_exposed: bool,
    dangling_kind: str | None = None,
) -> Severity:
    """Return the deterministic minimum severity for a finding."""
    if externally_exposed:
        return Severity.CRITICAL
    if rule == "unreachable-workload":
        return Severity.HIGH
    if rule == "dangling-reference" and dangling_kind in _SECRET_OR_CONFIG:
        return Severity.HIGH
    if rule in {"broken-selector", "dangling-reference", "orphaned-ingress"}:
        return Severity.MEDIUM
    return Severity.LOW


def raise_only(floor: Severity, proposed: Severity) -> Severity:
    """Enforce that an LLM-proposed severity cannot fall below the floor."""
    order = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }
    if order[proposed] < order[floor]:
        return floor
    return proposed
