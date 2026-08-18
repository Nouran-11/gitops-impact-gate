from __future__ import annotations

from pathlib import Path

import pytest
import yaml
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
    assert "demo/Deployment/checkout" in finding.path


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


def test_cli_selector_break_real_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Headline scenario through the CLI: matching before is clean; renamed after is critical."""
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    _copy_yaml_dir(root, before_dir)
    _copy_yaml_dir(root, after_dir)
    _set_pod_template_app(after_dir / "deployment.yaml", "checkout-v2")

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return []

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)

    before_result = runner.invoke(app, ["analyze", str(before_dir), "--no-cache"])
    assert before_result.exit_code == 0, before_result.output
    assert "## Relationship findings" not in before_result.output
    assert "broken-selector" not in before_result.output

    result = runner.invoke(
        app, ["analyze", str(after_dir), "--before", str(before_dir), "--no-cache"]
    )
    assert result.exit_code == 0, result.output
    assert "## Relationship findings" in result.output
    relationship = result.output.split("## Relationship findings", 1)[1]
    if "## Scanner findings" in relationship:
        relationship = relationship.split("## Scanner findings", 1)[0]
    headings = [line for line in relationship.splitlines() if line.startswith("### ")]
    broken = [line for line in headings if "broken-selector" in line]
    assert len(broken) == 1, result.output
    assert "critical" in broken[0]
    assert "demo/Ingress/public" in relationship
    assert "demo/Service/checkout" in relationship
    assert "**Risk:** high" in result.output


def test_cli_service_matches_pod_labels_not_match_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Correct Service must not fire when only Deployment.matchLabels disagrees."""
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    matching = tmp_path / "matching"
    _copy_yaml_dir(root, matching)
    _set_match_labels_app(matching / "deployment.yaml", "checkout-v2")

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return []

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(app, ["analyze", str(matching), "--no-cache"])
    assert result.exit_code == 0, result.output
    assert "broken-selector" not in result.output
    assert "mismatching-selector" in result.output


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

    scanner_finding = Finding(
        id=compute_finding_id("unset-cpu-requirements", "demo/Deployment/checkout", "cpu"),
        origin="scanner",
        rule="unset-cpu-requirements",
        resource=ResourceRef(
            api_version="apps/v1", kind="Deployment", name="checkout", namespace="demo"
        ),
        path=["demo/File/checkout"],
        evidence="deployment.yaml: container is missing cpu requests",
        severity_floor=Severity.LOW,
    )

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return [scanner_finding]

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(app, ["analyze", str(after_dir), "--before", str(before_dir)])
    assert result.exit_code == 0, result.output
    assert "**Risk:** high" in result.output
    assert "broken-selector" in result.output
    assert "demo/Ingress/public" in result.output
    assert "critical" in result.output
    assert "## Relationship findings" in result.output
    assert "## Scanner findings" not in result.output
    assert "unset-cpu-requirements" not in result.output
    mermaid = result.output.split("```mermaid", 1)[1].split("```", 1)[0]
    assert "-->" in mermaid
    assert "demo/Ingress/public" in mermaid
    assert "demo/Service/checkout" in mermaid
    assert "demo/Deployment/checkout" in mermaid
    assert "File/checkout" not in mermaid


def test_cli_selector_break_without_before_still_draws_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    after_dir = tmp_path / "after"
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    after_dir.mkdir()
    for path in root.glob("*.yaml"):
        (after_dir / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    deployment = (after_dir / "deployment.yaml").read_text(encoding="utf-8")
    (after_dir / "deployment.yaml").write_text(
        _relabel_pod_template(deployment),
        encoding="utf-8",
    )

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return []

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(app, ["analyze", str(after_dir)])
    assert result.exit_code == 0, result.output
    assert "broken-selector" in result.output
    assert "## Impact graph" in result.output
    assert "no impact" not in result.output
    mermaid = result.output.split("```mermaid", 1)[1].split("```", 1)[0]
    assert "demo/Ingress/public" in mermaid
    assert "demo/Service/checkout" in mermaid


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

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return [scanner_finding]

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "CKV_K8S_20" in result.output
    assert "**Risk:** high" in result.output
    assert "## Impact graph" not in result.output
    assert "no impact" not in result.output
    assert "```suggestion" not in result.output


def test_cli_before_drops_identical_scanner_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    _copy_yaml_dir(root, before_dir)
    _copy_yaml_dir(root, after_dir)
    _set_pod_template_app(after_dir / "deployment.yaml", "checkout-v2")

    scanner_findings = [
        Finding(
            id=compute_finding_id("KSV-0014", "_cluster/Kubernetes/deployment", "ro"),
            origin="scanner",
            rule="KSV-0014",
            resource=ResourceRef(api_version="v1", kind="Kubernetes", name="deployment"),
            path=["_cluster/Kubernetes/deployment"],
            evidence=(
                "deployment.yaml: Root file system is not read-only. "
                "Remediation: set readOnlyRootFilesystem."
            ),
            severity_floor=Severity.HIGH,
        ),
        Finding(
            id=compute_finding_id("KSV-0118", "_cluster/Kubernetes/deployment", "seccomp"),
            origin="scanner",
            rule="KSV-0118",
            resource=ResourceRef(api_version="v1", kind="Kubernetes", name="deployment"),
            path=["_cluster/Kubernetes/deployment"],
            evidence="deployment.yaml: seccomp profile is not set",
            severity_floor=Severity.HIGH,
        ),
        Finding(
            id=compute_finding_id("unset-cpu-requirements", "demo/Deployment/checkout", "cpu"),
            origin="scanner",
            rule="unset-cpu-requirements",
            resource=ResourceRef(
                api_version="apps/v1", kind="Deployment", name="checkout", namespace="demo"
            ),
            path=["demo/Deployment/checkout"],
            evidence="deployment.yaml: container is missing cpu requests",
            severity_floor=Severity.LOW,
        ),
    ]

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return list(scanner_findings)

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(
        app, ["analyze", str(after_dir), "--before", str(before_dir), "--no-cache"]
    )
    assert result.exit_code == 0, result.output
    assert "## Scanner findings" not in result.output
    assert "KSV-0014" not in result.output
    assert "KSV-0118" not in result.output
    assert "unset-cpu-requirements" not in result.output
    assert "## Relationship findings" in result.output
    relationship = result.output.split("## Relationship findings", 1)[1]
    assert "broken-selector" in relationship
    scanner_rules = {"KSV-0014", "KSV-0118", "unset-cpu-requirements"}
    headings = [line for line in relationship.splitlines() if line.startswith("### ")]
    for line in headings:
        assert not any(rule in line for rule in scanner_rules)
    allowed = {"broken-selector", "unreachable-workload", "mismatching-selector"}
    found_rules = {line.split("`")[1] for line in headings if "`" in line}
    assert found_rules <= allowed
    assert found_rules


def test_cli_scanner_keeps_own_text_not_graph_explanation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    after_dir = tmp_path / "after"
    _copy_yaml_dir(root, after_dir)
    _set_pod_template_app(after_dir / "deployment.yaml", "checkout-v2")
    evidence = (
        "deployment.yaml: Root file system is not read-only. "
        "Remediation: Set 'readOnlyRootFilesystem' to true."
    )
    scanner_finding = Finding(
        id=compute_finding_id("KSV-0014", "_cluster/Kubernetes/deployment", "ro"),
        origin="scanner",
        rule="KSV-0014",
        resource=ResourceRef(api_version="v1", kind="Kubernetes", name="deployment"),
        path=["_cluster/Kubernetes/deployment"],
        evidence=evidence,
        severity_floor=Severity.HIGH,
    )

    async def fake_scanners(_files: object, **_kwargs: object) -> list[Finding]:
        return [scanner_finding]

    monkeypatch.setattr("impactgate.cli.run_all_scanners", fake_scanners)
    result = runner.invoke(app, ["analyze", str(after_dir), "--no-cache"])
    assert result.exit_code == 0, result.output
    assert "## Scanner findings" in result.output
    scan = result.output.split("## Scanner findings", 1)[1]
    assert "KSV-0014" in scan
    assert evidence in scan
    assert "selector matches no pods" not in scan
    assert "_cluster/Kubernetes/deployment" not in scan.split(evidence, 1)[0]


def _copy_yaml_dir(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True)
    for path in src.glob("*.yaml"):
        (dest / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")


def _set_pod_template_app(path: Path, value: str) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["spec"]["template"]["metadata"]["labels"]["app"] = value
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _set_match_labels_app(path: Path, value: str) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["spec"]["selector"]["matchLabels"]["app"] = value
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


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
