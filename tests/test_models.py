from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from impactgate.cli import app
from impactgate.models import (
    Edge,
    EdgeKind,
    Finding,
    GateDecision,
    Resource,
    ResourceRef,
    Severity,
    Verdict,
    compute_finding_id,
)
from impactgate.report.markdown import render_report

runner = CliRunner()


def test_resource_ref_namespaced_key() -> None:
    ref = ResourceRef(
        api_version="apps/v1",
        kind="Deployment",
        name="checkout",
        namespace="demo",
    )
    assert ref.key() == "demo/Deployment/checkout"


def test_resource_ref_cluster_scoped_key() -> None:
    ref = ResourceRef(
        api_version="rbac.authorization.k8s.io/v1",
        kind="ClusterRole",
        name="admin",
    )
    assert ref.key() == "_cluster/ClusterRole/admin"


def test_finding_id_is_stable() -> None:
    first = compute_finding_id("broken-selector", "demo/Service/checkout", "app=checkout", "abc")
    second = compute_finding_id("broken-selector", "demo/Service/checkout", "app=checkout", "abc")
    assert first == second
    assert len(first) == 64


def test_finding_id_changes_with_fingerprint() -> None:
    a = compute_finding_id("broken-selector", "demo/Service/checkout", "app=checkout", "fp-a")
    b = compute_finding_id("broken-selector", "demo/Service/checkout", "app=checkout", "fp-b")
    assert a != b


def test_empty_gate_decision_round_trip() -> None:
    decision = GateDecision(risk="low", verdicts=[], reason="no findings")
    restored = GateDecision.model_validate_json(decision.model_dump_json())
    assert restored == decision


def test_models_accept_spec_shapes() -> None:
    ref = ResourceRef(api_version="v1", kind="Service", name="checkout", namespace="demo")
    resource = Resource(ref=ref, spec={"kind": "Service"}, source_file="svc.yaml", source_line=1)
    edge = Edge(
        source=ref.key(),
        target="demo/Deployment/checkout",
        kind=EdgeKind.SELECTS,
        detail="selector app=checkout",
    )
    finding = Finding(
        id=compute_finding_id("broken-selector", ref.key(), edge.detail),
        origin="graph",
        rule="broken-selector",
        resource=ref,
        path=["demo/Ingress/public", ref.key()],
        evidence=edge.detail,
        severity_floor=Severity.HIGH,
    )
    verdict = Verdict(
        finding_id=finding.id,
        severity=Severity.HIGH,
        explanation="Service selector matches no pods.",
        suggested_fix=None,
        confidence=0.9,
    )
    assert resource.source_line == 1
    assert finding.origin == "graph"
    assert verdict.suggested_fix is None


def test_cli_analyze_prints_empty_report(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "**Risk:** low" in result.output
    assert "No findings." in result.output
    assert "no findings" in result.output


def test_cli_help_lists_analyze() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    assert "analyze" in result.output


def test_cli_analyze_missing_dir_fails(tmp_path: Path) -> None:
    result = runner.invoke(app, ["analyze", str(tmp_path / "missing")])
    assert result.exit_code != 0


def test_render_report_includes_verdicts() -> None:
    decision = GateDecision(
        risk="high",
        reason="new graph findings",
        verdicts=[
            Verdict(
                finding_id="abc",
                severity=Severity.HIGH,
                explanation="Selector matches no pods.",
                suggested_fix="app: checkout",
                confidence=0.8,
            )
        ],
    )
    rendered = render_report(decision)
    assert "**Risk:** high" in rendered
    assert "Selector matches no pods." in rendered
    assert "```suggestion" in rendered
    assert "## Relationship findings" in rendered
