"""Cluster-shaped controller tests: real YAML as API objects, kopf handlers, HTTP metrics.

These would have failed on a kind cluster while the unit tests stayed green:
policy lookup never ran, the managed label lived on the Deployment, and nothing
served GET /metrics in the controller process.
"""

from __future__ import annotations

import logging
import urllib.request
from pathlib import Path
from typing import Any

import kopf
import yaml
from pytest import MonkeyPatch
from typer.testing import CliRunner

from impactgate.controller.actions import Action
from impactgate.controller.watcher import (
    Debouncer,
    NullClusterClient,
    handle_pod_event,
    handle_policy_event,
    handle_startup,
    is_managed,
    reset_runtime,
)
from impactgate.metrics import stop_http_server

from tests.test_controller import RecordingClusterClient, _healthy_revision

ROOT = Path(__file__).resolve().parents[1]
DEMO_DEPLOYMENTS = (
    "demo/manifests/bad-image/deployment.yaml",
    "demo/manifests/real-bug/deployment.yaml",
    "demo/manifests/selector-break/deployment.yaml",
)


def _load_yaml(relative: str) -> dict[str, Any]:
    loaded = yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def replica_pod_from_deployment(
    deployment: dict[str, Any],
    *,
    reason: str = "ErrImagePull",
) -> dict[str, Any]:
    """Shape a Pod the way the API server does: labels come only from the template."""
    meta = deployment["metadata"]
    assert isinstance(meta, dict)
    template = deployment["spec"]["template"]
    assert isinstance(template, dict)
    tmpl_meta = template.get("metadata") or {}
    assert isinstance(tmpl_meta, dict)
    labels = dict(tmpl_meta.get("labels") or {})
    name = str(meta["name"])
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"{name}-57c775bfc-n66zk",
            "namespace": meta.get("namespace", "default"),
            "labels": labels,
            "ownerReferences": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": f"{name}-57c775bfc",
                }
            ],
        },
        "spec": dict(template.get("spec") or {}),
        "status": {
            "phase": "Pending",
            "containerStatuses": [
                {
                    "name": name,
                    "ready": False,
                    "state": {
                        "waiting": {"reason": reason, "message": "manifest unknown"},
                    },
                }
            ],
        },
    }


def test_crd_yaml_is_definition_only() -> None:
    docs = [doc for doc in yaml.safe_load_all((ROOT / "deploy/crd.yaml").read_text()) if doc]
    assert len(docs) == 1
    assert docs[0]["kind"] == "CustomResourceDefinition"
    instance = _load_yaml("deploy/policy.yaml")
    assert instance["kind"] == "RemediationPolicy"
    assert instance["metadata"]["name"] == "default"
    assert instance["metadata"]["namespace"] == "demo"


def test_demo_pod_templates_carry_managed_label() -> None:
    for relative in DEMO_DEPLOYMENTS:
        deployment = _load_yaml(relative)
        template_labels = deployment["spec"]["template"]["metadata"]["labels"]
        assert template_labels["impactgate.io/managed"] == "true", relative
        pod = replica_pod_from_deployment(deployment)
        assert is_managed(pod), relative


def test_deployment_metadata_label_does_not_reach_the_pod() -> None:
    deployment = _load_yaml("demo/manifests/bad-image/deployment.yaml")
    deployment["metadata"]["labels"] = {"impactgate.io/managed": "true"}
    deployment["spec"]["template"]["metadata"]["labels"] = {"app": "storefront"}
    pod = replica_pod_from_deployment(deployment)
    assert is_managed(pod) is False


def test_kopf_registry_watches_policies_and_pods() -> None:
    registry = kopf.get_default_registry()
    watching = {handler.fn for handler in registry._watching.get_all_handlers()}
    activities = {handler.fn for handler in registry._activities.get_all_handlers()}
    assert handle_policy_event in watching
    assert handle_pod_event in watching
    assert handle_startup in activities


def test_kopf_handlers_load_namespaced_policy_not_default(
    caplog: logging.LogCaptureFixture,
) -> None:
    """RemediationPolicy/default in demo must win over default_policy()."""
    client = RecordingClusterClient(
        workload_name="storefront",
        revisions=[_healthy_revision()],
    )
    reset_runtime(client=client, debouncer=Debouncer(threshold=1))
    caplog.set_level(logging.INFO, logger="impactgate.controller")

    policy = _load_yaml("deploy/policy.yaml")
    policy["spec"]["mode"] = "enforce"
    handle_policy_event(body=policy, type="ADDED")

    deployment = _load_yaml("demo/manifests/bad-image/deployment.yaml")
    pod = replica_pod_from_deployment(deployment, reason="ErrImagePull")
    assert is_managed(pod)

    action = handle_pod_event(body=pod)
    assert action == Action.ROLLBACK
    assert client.rollbacks == [("demo", "storefront", "storefront-healthy")]
    messages = "\n".join(record.message for record in caplog.records)
    assert "mode=dry-run, allowed=[]" not in messages
    assert "loaded RemediationPolicy demo/default mode=enforce" in messages
    assert "allowed=['rollback', 'restart']" in messages


def test_missing_policy_stays_silent_default(caplog: logging.LogCaptureFixture) -> None:
    reset_runtime(client=NullClusterClient(), debouncer=Debouncer(threshold=1))
    caplog.set_level(logging.INFO, logger="impactgate.controller")
    deployment = _load_yaml("demo/manifests/bad-image/deployment.yaml")
    handle_pod_event(body=replica_pod_from_deployment(deployment, reason="ErrImagePull"))
    messages = "\n".join(record.message for record in caplog.records)
    assert "allowed=[]" in messages
    assert "mode=dry-run" in messages


def test_controller_cli_requires_enabled_flag(monkeypatch: MonkeyPatch) -> None:
    from impactgate.cli import app

    monkeypatch.delenv("IMPACTGATE_CONTROLLER_ENABLED", raising=False)
    result = CliRunner().invoke(app, ["controller"])
    assert result.exit_code == 1
    assert "IMPACTGATE_CONTROLLER_ENABLED" in result.output


def test_controller_cli_documents_metrics_port() -> None:
    from impactgate.cli import app

    result = CliRunner().invoke(app, ["controller", "--help"])
    assert result.exit_code == 0
    assert "--metrics-port" in result.stdout


def test_controller_startup_serves_metrics(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("IMPACTGATE_METRICS_PORT", "0")
    stop_http_server()
    port = handle_startup()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
            body = response.read().decode("utf-8")
            status = response.status
        assert status == 200
        assert "impactgate_remediation_total" in body
        assert "impactgate_time_to_recovery_seconds" in body
    finally:
        stop_http_server()
