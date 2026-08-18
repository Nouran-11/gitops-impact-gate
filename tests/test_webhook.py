from __future__ import annotations

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from impactgate.github.client import RecordingPoster
from impactgate.github.webhook import create_app, verify_signature
from impactgate.models import GateDecision
from impactgate.report.markdown import COMMENT_MARKER, render_report, status_for_risk
from impactgate.report.mermaid import from_paths


def _sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_verify_signature_accepts_valid_hmac() -> None:
    body = b'{"ok": true}'
    assert verify_signature("s3cret", body, _sign("s3cret", body))
    assert not verify_signature("s3cret", body, _sign("other", body))
    assert not verify_signature("s3cret", body, None)


def test_unsigned_webhook_is_rejected() -> None:
    client = TestClient(create_app(secret="s3cret", poster=RecordingPoster()))
    response = client.post("/webhook", content=b"{}", headers={"X-GitHub-Event": "ping"})
    assert response.status_code == 401


def test_non_pr_event_is_ignored() -> None:
    poster = RecordingPoster()
    app = create_app(secret="s3cret", poster=poster)
    body = b'{"action":"created"}'
    response = TestClient(app).post(
        "/webhook",
        content=body,
        headers={"X-GitHub-Event": "ping", "X-Hub-Signature-256": _sign("s3cret", body)},
    )
    assert response.status_code == 200
    assert poster.comments == []
    assert poster.checks == []


def test_opened_pr_posts_comment_and_failure_check() -> None:
    poster = RecordingPoster()

    async def analyzer(_payload: dict[str, object]) -> GateDecision:
        return GateDecision(risk="high", verdicts=[], reason="broken-selector")

    app = create_app(secret="s3cret", poster=poster, analyzer=analyzer)
    payload = {
        "action": "opened",
        "pull_request": {"number": 7, "head": {"sha": "abc123"}, "base": {"sha": "def456"}},
        "repository": {"full_name": "acme/demo", "clone_url": "https://github.com/acme/demo.git"},
    }
    body = json.dumps(payload).encode()
    response = TestClient(app).post(
        "/webhook",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign("s3cret", body),
        },
    )
    assert response.status_code == 200
    assert poster.comments
    repo, number, comment = poster.comments[0]
    assert repo == "acme/demo"
    assert number == 7
    assert COMMENT_MARKER in comment
    assert poster.checks == [("acme/demo", "abc123", "failure")]


def test_status_mapping() -> None:
    assert status_for_risk("low") == "success"
    assert status_for_risk("medium") == "neutral"
    assert status_for_risk("high") == "failure"


def test_mermaid_from_selector_break_path() -> None:
    source = from_paths(
        [["demo/Ingress/public", "demo/Service/checkout", "demo/Deployment/checkout", "(no pods)"]]
    )
    assert "flowchart LR" in source
    assert "Ingress" in source
    assert "Service" in source
    assert "Deployment" in source
    assert "-->" in source
    assert "(no pods)" not in source
    assert "demo_Ingress_public --> demo_Service_checkout" in source
    assert "demo_Service_checkout --> demo_Deployment_checkout" in source


def test_mermaid_omits_scanner_pseudo_nodes() -> None:
    source = from_paths(
        [
            ["demo/File/checkout"],
            ["_cluster/Kubernetes/deployment"],
            ["demo/Ingress/public", "demo/Service/checkout"],
        ]
    )
    assert "File" not in source
    assert "Kubernetes" not in source
    assert "demo/Ingress/public" in source
    assert "-->" in source


def test_mermaid_empty_paths_returns_blank() -> None:
    assert from_paths([]) == ""
    assert from_paths([["demo/File/checkout"], ["(no pods)"]]) == ""
    assert "no impact" not in from_paths([])


def test_render_report_includes_marker_and_mermaid() -> None:
    decision = GateDecision(risk="low", verdicts=[], reason="no findings")
    rendered = render_report(
        decision,
        paths=[["demo/Ingress/public", "demo/Service/checkout"]],
    )
    assert COMMENT_MARKER in rendered
    assert "```mermaid" in rendered
    assert "demo/Ingress/public" in rendered
