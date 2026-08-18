from __future__ import annotations

from impactgate.analysis.severity import accepted_suggested_fix, raise_only, severity_floor
from impactgate.models import Severity


def test_externally_exposed_is_critical() -> None:
    assert (
        severity_floor("broken-selector", externally_exposed=True) == Severity.CRITICAL
    )


def test_unreachable_workload_is_high() -> None:
    assert (
        severity_floor("unreachable-workload", externally_exposed=False) == Severity.HIGH
    )


def test_secret_dangle_is_high() -> None:
    assert (
        severity_floor("dangling-reference", externally_exposed=False, dangling_kind="Secret")
        == Severity.HIGH
    )


def test_internal_broken_selector_is_medium() -> None:
    assert (
        severity_floor("broken-selector", externally_exposed=False) == Severity.MEDIUM
    )


def test_scanner_style_rule_is_low_without_exposure() -> None:
    assert (
        severity_floor("unset-cpu-requirements", externally_exposed=False) == Severity.LOW
    )


def test_raise_only_never_lowers() -> None:
    assert raise_only(Severity.HIGH, Severity.LOW) == Severity.HIGH
    assert raise_only(Severity.MEDIUM, Severity.CRITICAL) == Severity.CRITICAL


def test_accepted_suggested_fix_graph_only_above_threshold() -> None:
    patch = "spec:\n  selector:\n    app: checkout"
    assert accepted_suggested_fix("graph", patch, 0.8) == patch
    assert accepted_suggested_fix("graph", patch, 0.79) is None
    assert accepted_suggested_fix("scanner", patch, 0.99) is None
    assert accepted_suggested_fix("graph", "   ", 0.95) is None
    assert accepted_suggested_fix("graph", None, 0.95) is None
