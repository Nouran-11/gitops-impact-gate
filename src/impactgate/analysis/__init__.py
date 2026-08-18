"""Graph-level integrity checks and blast-radius traversal."""

from impactgate.analysis.impact import ImpactResult, compute_impact, to_gate_decision
from impactgate.analysis.rules import run_integrity_checks
from impactgate.analysis.severity import raise_only, severity_floor

__all__ = [
    "ImpactResult",
    "compute_impact",
    "raise_only",
    "run_integrity_checks",
    "severity_floor",
    "to_gate_decision",
]
