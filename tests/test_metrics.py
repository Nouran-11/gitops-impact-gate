from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from impactgate.controller.policy import default_policy
from impactgate.controller.watcher import Debouncer, handle_failure, maybe_record_recovery
from impactgate.github.client import RecordingPoster
from impactgate.github.webhook import create_app
from impactgate.metrics import REGISTRY

from tests.test_controller import NOW, RecordingClusterClient, _pod

REQUIRED_METRICS = (
    "impactgate_findings_total",
    "impactgate_gate_decisions_total",
    "impactgate_llm_calls_total",
    "impactgate_analysis_duration_seconds",
    "impactgate_remediation_total",
    "impactgate_time_to_recovery_seconds",
)


def _ready_pod() -> dict[str, object]:
    return {
        "metadata": {
            "name": "checkout-0",
            "namespace": "demo",
            "labels": {"impactgate.io/managed": "true"},
        },
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"name": "app", "ready": True, "state": {"running": {}}}
            ],
        },
    }


def test_prometheus_text_includes_required_series() -> None:
    REGISTRY.record_finding("broken-selector", "critical", "graph")
    REGISTRY.record_gate("high")
    REGISTRY.record_llm("fake", cached=False)
    REGISTRY.record_analysis(0.2)
    REGISTRY.record_remediation("rollback", "dry-run")
    REGISTRY.note_detection("demo/storefront", at=0.0)
    REGISTRY.note_recovery("demo/storefront", at=12.0)
    text = REGISTRY.render()
    for name in REQUIRED_METRICS:
        assert name in text
    assert "origin=\"graph\"} 1" in text
    assert "broken-selector" in text
    assert "impactgate_time_to_recovery_seconds_sum 12.0" in text


def test_mttr_starts_at_detection_not_action() -> None:
    client = RecordingClusterClient(workload_name="storefront")
    debouncer = Debouncer(threshold=3)
    for offset in (0, 1, 2):
        handle_failure(
            _pod(reason="ImagePullBackOff"),
            reason="ImagePullBackOff",
            client=client,
            debouncer=debouncer,
            policy=default_policy(),
            now=NOW + timedelta(minutes=offset),
        )
    elapsed = maybe_record_recovery(
        _ready_pod(),
        client=client,
        now=NOW + timedelta(minutes=3),
    )
    assert elapsed == 180.0
    text = REGISTRY.render()
    assert 'impactgate_time_to_recovery_seconds_bucket{le="120"} 0' in text
    assert 'impactgate_time_to_recovery_seconds_bucket{le="300"} 1' in text
    assert "impactgate_remediation_total" in text
    assert 'action="rollback"' in text


def test_metrics_endpoint_does_not_require_hmac() -> None:
    app = create_app(secret="s3cret", poster=RecordingPoster())
    response = TestClient(app).get("/metrics")
    assert response.status_code == 200
    assert "impactgate_time_to_recovery_seconds" in response.text
    assert response.headers["content-type"].startswith("text/plain")


def test_controller_metrics_http_server_exposes_registry() -> None:
    import urllib.request

    from impactgate.metrics import start_http_server, stop_http_server

    REGISTRY.record_remediation("rollback", "executed")
    port = start_http_server(0, addr="127.0.0.1")
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
            body = response.read().decode("utf-8")
            status = response.status
        assert status == 200
        assert "impactgate_remediation_total" in body
        assert 'action="rollback"' in body
    finally:
        stop_http_server()


def test_grafana_dashboard_has_mttr_panel() -> None:
    path = Path(__file__).resolve().parents[1] / "deploy" / "grafana-dashboard.json"
    dashboard = json.loads(path.read_text(encoding="utf-8"))
    titles = [str(panel.get("title", "")) for panel in dashboard["panels"]]
    assert any("MTTR" in title for title in titles)
    exprs = [
        str(target.get("expr", ""))
        for panel in dashboard["panels"]
        for target in panel.get("targets", [])
    ]
    assert any("impactgate_time_to_recovery_seconds" in expr for expr in exprs)
