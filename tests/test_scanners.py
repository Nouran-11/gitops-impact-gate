from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id
from impactgate.scanners import deduplicate, run_all_scanners
from impactgate.scanners.base import run_command
from impactgate.scanners.checkov import parse_checkov_json
from impactgate.scanners.kubelinter import parse_kubelinter_json
from impactgate.scanners.trivy import parse_trivy_json


def test_parse_checkov_failed_checks(tmp_path: Path) -> None:
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_20",
                    "check_name": "Containers should not run as root",
                    "resource": "Deployment.demo.checkout",
                    "severity": "HIGH",
                }
            ]
        }
    }
    findings = parse_checkov_json(json.dumps(payload), tmp_path / "deployment.yaml")
    assert len(findings) == 1
    assert findings[0].origin == "scanner"
    assert findings[0].rule == "CKV_K8S_20"
    assert findings[0].resource.key() == "demo/Deployment/checkout"
    assert findings[0].severity_floor == Severity.HIGH


def test_parse_trivy_misconfigurations(tmp_path: Path) -> None:
    payload = {
        "Results": [
            {
                "Target": "deployment.yaml",
                "Misconfigurations": [
                    {
                        "ID": "KSV001",
                        "Title": "Process can elevate its own privileges",
                        "Severity": "MEDIUM",
                    }
                ],
            }
        ]
    }
    findings = parse_trivy_json(json.dumps(payload), tmp_path / "deployment.yaml")
    assert findings[0].rule == "KSV001"
    assert findings[0].origin == "scanner"


def test_parse_kubelinter_reports(tmp_path: Path) -> None:
    payload = {
        "Reports": [
            {
                "Check": "unset-cpu-requirements",
                "Diagnostic": {"Message": "container is missing cpu requests"},
                "Object": {
                    "K8sObject": {
                        "Kind": "Deployment",
                        "Namespace": "demo",
                        "Name": "checkout",
                    }
                },
            }
        ]
    }
    findings = parse_kubelinter_json(json.dumps(payload), tmp_path / "deployment.yaml")
    assert findings[0].rule == "unset-cpu-requirements"
    assert findings[0].resource.key() == "demo/Deployment/checkout"


def test_deduplicate_same_rule_and_resource() -> None:
    ref = ResourceRef(api_version="apps/v1", kind="Deployment", name="checkout", namespace="demo")
    first = Finding(
        id=compute_finding_id("CKV_K8S_20", ref.key(), "a"),
        origin="scanner",
        rule="CKV_K8S_20",
        resource=ref,
        path=[ref.key()],
        evidence="a",
        severity_floor=Severity.HIGH,
    )
    second = first.model_copy(update={"evidence": "b"})
    assert len(deduplicate([first, second])) == 1


def test_missing_binaries_do_not_crash(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def missing(_binary: str, _args: object) -> None:
        return None

    monkeypatch.setattr("impactgate.scanners.checkov.run_command", missing)
    monkeypatch.setattr("impactgate.scanners.trivy.run_command", missing)
    monkeypatch.setattr("impactgate.scanners.kubelinter.run_command", missing)

    async def _run() -> list[Finding]:
        return await run_all_scanners([tmp_path / "deployment.yaml"])

    assert asyncio.run(_run()) == []


def test_run_command_skips_missing_binary() -> None:
    result = asyncio.run(run_command("impactgate-no-such-scanner", ["--help"]))
    assert result is None
