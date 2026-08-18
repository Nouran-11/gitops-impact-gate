from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from impactgate.analysis.impact import compute_impact
from impactgate.cli import app
from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id

from tests.helpers import graph_from_yaml, selector_break_graphs

runner = CliRunner()


def test_selector_break_reports_exposed_broken_selector() -> None:
    before, after, changed_files = selector_break_graphs()
    result = compute_impact(before, after, changed_files)
    broken = [item for item in result.findings if item.rule == "broken-selector"]
    assert len(broken) == 1
    finding = broken[0]
    assert finding.resource.key() == "demo/Service/checkout"
    assert finding.path[0] == "demo/Ingress/public"
    assert "demo/Service/checkout" in finding.path
    assert finding.severity_floor == Severity.CRITICAL
    assert "checkout" in finding.evidence


def test_internal_broken_selector_is_medium() -> None:
    before = graph_from_yaml(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      containers: [{name: app, image: nginx:1.25}]
---
apiVersion: v1
kind: Service
metadata: {name: checkout, namespace: demo}
spec:
  selector: {app: checkout}
"""
    )
    after = graph_from_yaml(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout-v2}}
  template:
    metadata: {labels: {app: checkout-v2}}
    spec:
      containers: [{name: app, image: nginx:1.25}]
---
apiVersion: v1
kind: Service
metadata: {name: checkout, namespace: demo}
spec:
  selector: {app: checkout}
"""
    )
    result = compute_impact(before, after, ["deployment.yaml"])
    broken = [item for item in result.findings if item.rule == "broken-selector"]
    assert broken[0].severity_floor == Severity.MEDIUM


def test_cli_selector_break_after_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    for target in (before_dir, after_dir):
        target.mkdir()
        for path in root.glob("*.yaml"):
            (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    deployment = (after_dir / "deployment.yaml").read_text(encoding="utf-8")
    (after_dir / "deployment.yaml").write_text(
        _relabel_pod_template(deployment),
        encoding="utf-8",
    )

    async def no_scanners(_files: object) -> list[Finding]:
        return []

    monkeypatch.setattr("impactgate.cli.run_all_scanners", no_scanners)
    result = runner.invoke(app, ["analyze", str(after_dir), "--before", str(before_dir)])
    assert result.exit_code == 0, result.output
    assert "**Risk:** high" in result.output
    assert "broken-selector" in result.output
    assert "demo/Ingress/public" in result.output


def test_cli_merges_scanner_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "cm.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n  namespace: demo\n",
        encoding="utf-8",
    )
    ref = ResourceRef(api_version="v1", kind="ConfigMap", name="ok", namespace="demo")
    scanner_finding = Finding(
        id=compute_finding_id("CKV_K8S_20", ref.key(), "root"),
        origin="scanner",
        rule="CKV_K8S_20",
        resource=ref,
        path=[ref.key()],
        evidence="deployment.yaml: containers should not run as root",
        severity_floor=Severity.HIGH,
    )

    async def fake_scanners(_files: object) -> list[Finding]:
        return [scanner_finding]

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "CKV_K8S_20" in result.output
    assert "**Risk:** high" in result.output


def _relabel_pod_template(text: str) -> str:
    lines = text.splitlines(keepends=True)
    seen_template = False
    rewritten: list[str] = []
    for line in lines:
        if "template:" in line:
            seen_template = True
        if seen_template and line.strip() == "app: checkout":
            rewritten.append(line.replace("app: checkout", "app: checkout-v2"))
            seen_template = False
            continue
        rewritten.append(line)
    return "".join(rewritten)
