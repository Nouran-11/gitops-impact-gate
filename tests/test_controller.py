from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from impactgate.controller.actions import (
    Action,
    AuditRecord,
    CircuitBreaker,
    Diagnosis,
    ReplicaSetRevision,
    classify_failure,
    last_healthy_revision,
    scaled_memory,
)
from impactgate.controller.cluster import (
    KubernetesClusterClient,
    NullClusterClient,
    workload_from_pod,
)
from impactgate.controller.policy import RemediationPolicy, default_policy, policy_from_crd
from impactgate.controller.watcher import (
    Debouncer,
    _decode_log_text,
    _logs_via_incluster,
    _logs_via_kubectl,
    _logs_via_kubernetes,
    compress_logs,
    diagnose,
    extract_runtime_evidence,
    extract_waiting_reason,
    handle_failure,
    is_managed,
    read_pod_logs,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@dataclass
class RecordingClusterClient:
    logs: str = ""
    current: str = ""
    events: list[str] = field(default_factory=list)
    workload_name: str = "storefront"
    revisions: list[ReplicaSetRevision] = field(default_factory=list)
    memory_limit: str = "256Mi"
    rollbacks: list[tuple[str, str, str]] = field(default_factory=list)
    memory_bumps: list[tuple[str, str, str]] = field(default_factory=list)
    restarts: list[tuple[str, str]] = field(default_factory=list)
    audits: list[AuditRecord] = field(default_factory=list)
    emitted: list[str] = field(default_factory=list)

    def previous_logs(self, namespace: str, pod: str) -> str:
        del namespace, pod
        return self.logs

    def current_logs(self, namespace: str, pod: str) -> str:
        del namespace, pod
        return self.current

    def pod_events(self, namespace: str, pod: str) -> list[str]:
        del namespace, pod
        return list(self.events)

    def owning_workload(self, namespace: str, pod: dict[str, Any]) -> str:
        del namespace, pod
        return self.workload_name

    def replicaset_history(self, namespace: str, workload: str) -> list[str]:
        del namespace, workload
        return [item.name for item in self.revisions]

    def list_revisions(self, namespace: str, workload: str) -> list[ReplicaSetRevision]:
        del namespace, workload
        return list(self.revisions)

    def rollback(self, namespace: str, workload: str, revision: str) -> str:
        self.rollbacks.append((namespace, workload, revision))
        return f"rolled-back:{revision}"

    def current_memory_limit(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return self.memory_limit

    def bump_memory(self, namespace: str, workload: str, new_limit: str) -> str:
        self.memory_bumps.append((namespace, workload, new_limit))
        return f"memory-bumped:{new_limit}"

    def restart(self, namespace: str, workload: str) -> str:
        self.restarts.append((namespace, workload))
        return "restarted"

    def scale_out(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "scaled-out"

    def emit_event(self, namespace: str, workload: str, message: str) -> None:
        self.emitted.append(f"{namespace}/{workload}: {message}")

    def record_audit(self, record: AuditRecord) -> None:
        self.audits.append(record)


def _healthy_revision(name: str = "storefront-healthy") -> ReplicaSetRevision:
    return ReplicaSetRevision(
        name=name,
        desired=1,
        ready=1,
        ready_since=NOW - timedelta(minutes=15),
    )


def _enforce(*allowed: Action) -> RemediationPolicy:
    actions = list(allowed) or [Action.ROLLBACK, Action.RESTART]
    return RemediationPolicy(
        mode="enforce",
        min_confidence=0.8,
        allowed_actions=actions,
        max_actions_per_hour=2,
        memory_bump_factor=1.5,
        memory_limit_ceiling="2Gi",
    )


def _pod(*, reason: str, managed: bool = True, oom: bool = False) -> dict[str, object]:
    waiting = {"reason": reason} if not oom else {}
    terminated = {"reason": "OOMKilled"} if oom else {}
    return {
        "metadata": {
            "name": "checkout-0",
            "namespace": "demo",
            "labels": {"impactgate.io/managed": "true" if managed else "false"},
        },
        "status": {
            "containerStatuses": [
                {
                    "name": "app",
                    "state": {"waiting": waiting} if waiting else {"running": {}},
                    "lastState": {"terminated": terminated},
                }
            ]
        },
    }


REAL_BUG_TRACEBACK = "Traceback (most recent call last):\nValueError: boom"
REAL_BUG_ARGS = (
    "echo 'Traceback (most recent call last):'; echo 'ValueError: boom'; exit 1"
)


def _real_bug_live_pod(*, include_traceback_in_args: bool = True) -> dict[str, object]:
    """Shape of the kind pod after applying demo/manifests/real-bug/broken.patch."""
    args = [REAL_BUG_ARGS] if include_traceback_in_args else ["python", "/app.py"]
    return {
        "metadata": {
            "name": "payments-7c54d8f58f-hrc87",
            "namespace": "demo",
            "labels": {
                "app": "payments",
                "impactgate.io/managed": "true",
                "pod-template-hash": "7c54d8f58f",
            },
            "ownerReferences": [
                {"kind": "ReplicaSet", "name": "payments-7c54d8f58f", "controller": True}
            ],
        },
        "spec": {
            "containers": [
                {
                    "name": "payments",
                    "image": "nginx:1.25",
                    "command": ["/bin/sh", "-c"] if include_traceback_in_args else ["python"],
                    "args": args if include_traceback_in_args else ["/app.py"],
                }
            ]
        },
        "status": {
            "containerStatuses": [
                {
                    "name": "payments",
                    "state": {
                        "waiting": {
                            "reason": "CrashLoopBackOff",
                            "message": "back-off restarting failed container=payments",
                        }
                    },
                    "lastState": {
                        "terminated": {
                            "exitCode": 1,
                            "reason": "Error",
                            "message": "",
                        }
                    },
                }
            ]
        },
    }


def test_classify_image_pull_is_rollback() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="storefront",
        reason="ImagePullBackOff",
        compressed_logs="",
        events=[],
        managed=True,
    )
    assert classify_failure(diagnosis) == Action.ROLLBACK


def test_classify_app_bug_is_escalate() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="payments",
        reason="CrashLoopBackOff",
        compressed_logs="Traceback (most recent call last):\nValueError: boom",
        events=[],
        managed=True,
    )
    assert classify_failure(diagnosis) == Action.ESCALATE


def test_classify_oom_is_bump_memory() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="storefront",
        reason="CrashLoopBackOff",
        compressed_logs="lastState: OOMKilled",
        events=[],
        managed=True,
    )
    assert classify_failure(diagnosis) == Action.BUMP_MEMORY


def test_debounce_requires_threshold() -> None:
    debouncer = Debouncer(threshold=3, window=timedelta(minutes=5))
    start = datetime(2026, 1, 1, tzinfo=UTC)
    assert debouncer.record("demo/app", start) is False
    assert debouncer.record("demo/app", start + timedelta(minutes=1)) is False
    assert debouncer.record("demo/app", start + timedelta(minutes=2)) is True


def test_compress_logs_collapses_repeats() -> None:
    raw = "ready\nerror\nerror\nerror\ndone\n"
    compressed = compress_logs(raw)
    assert compressed.count("error") == 1
    assert "repeated 2 more times" in compressed


def test_extract_waiting_reason() -> None:
    assert extract_waiting_reason(_pod(reason="CrashLoopBackOff")) == "CrashLoopBackOff"
    assert extract_waiting_reason(_pod(reason="Running", oom=True)) == "OOMKilled"


def test_unmanaged_pods_are_skipped() -> None:
    assert is_managed(_pod(reason="CrashLoopBackOff", managed=False)) is False


def test_dry_run_logs_intended_action(caplog: logging.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="impactgate.controller")
    debouncer = Debouncer(threshold=1)
    action = handle_failure(
        _pod(reason="ImagePullBackOff"),
        reason="ImagePullBackOff",
        client=NullClusterClient(),
        debouncer=debouncer,
        policy=default_policy(),
    )
    assert action == Action.ROLLBACK
    assert any("dry-run: would rollback" in rec.message for rec in caplog.records)


def test_policy_from_crd_and_default() -> None:
    policy = policy_from_crd(
        {
            "mode": "enforce",
            "minConfidence": 0.9,
            "allowedActions": ["rollback", "restart"],
            "maxActionsPerHour": 2,
        }
    )
    assert policy.mode == "enforce"
    assert Action.ROLLBACK in policy.allowed_actions
    assert default_policy().dry_run is True
    assert default_policy().allowed_actions == []


def test_last_healthy_revision_requires_ten_minutes() -> None:
    too_new = ReplicaSetRevision(
        name="rs-new",
        desired=1,
        ready=1,
        ready_since=NOW - timedelta(minutes=3),
    )
    not_ready = ReplicaSetRevision(name="rs-bad", desired=1, ready=0, ready_since=None)
    healthy = _healthy_revision()
    assert last_healthy_revision([too_new, not_ready], now=NOW) is None
    assert last_healthy_revision([too_new, not_ready, healthy], now=NOW) == healthy


def test_scaled_memory_respects_ceiling() -> None:
    assert scaled_memory("256Mi", 1.5, "2Gi") == "384Mi"
    assert scaled_memory("2Gi", 1.5, "2Gi") == "2Gi"


def test_enforce_rollback_targets_healthy_revision() -> None:
    client = RecordingClusterClient(
        workload_name="storefront",
        revisions=[
            ReplicaSetRevision(name="storefront-bad", desired=1, ready=0),
            _healthy_revision(),
        ],
    )
    action = handle_failure(
        _pod(reason="ImagePullBackOff"),
        reason="ImagePullBackOff",
        client=client,
        debouncer=Debouncer(threshold=1),
        policy=_enforce(Action.ROLLBACK, Action.RESTART),
        breaker=CircuitBreaker(max_per_hour=2),
        now=NOW,
    )
    assert action == Action.ROLLBACK
    assert client.rollbacks == [("demo", "storefront", "storefront-healthy")]
    assert client.audits and client.audits[0].outcome.startswith("rolled-back")
    assert client.emitted


def test_rollback_without_healthy_revision_escalates() -> None:
    client = RecordingClusterClient(
        revisions=[ReplicaSetRevision(name="storefront-bad", desired=1, ready=0)],
    )
    action = handle_failure(
        _pod(reason="ImagePullBackOff"),
        reason="ImagePullBackOff",
        client=client,
        debouncer=Debouncer(threshold=1),
        policy=_enforce(Action.ROLLBACK),
        now=NOW,
    )
    assert action == Action.ESCALATE
    assert client.rollbacks == []
    assert client.audits[0].classification == Action.ROLLBACK
    assert client.audits[0].action == Action.ESCALATE


def test_confidence_floor_forces_escalate() -> None:
    diagnosis = Diagnosis(
        namespace="demo",
        pod="x",
        workload="storefront",
        reason="ImagePullBackOff",
        compressed_logs="",
        events=[],
        managed=True,
        confidence=0.4,
    )
    from impactgate.controller.actions import apply_guardrails

    chosen = apply_guardrails(
        diagnosis,
        Action.ROLLBACK,
        _enforce(Action.ROLLBACK),
        revisions=[_healthy_revision()],
        breaker=CircuitBreaker(),
        now=NOW,
    )
    assert chosen == Action.ESCALATE


def test_circuit_breaker_caps_actions_per_hour() -> None:
    breaker = CircuitBreaker(max_per_hour=2)
    client = RecordingClusterClient(revisions=[_healthy_revision()])
    policy = _enforce(Action.ROLLBACK)
    for offset in (0, 1, 2):
        handle_failure(
            _pod(reason="ImagePullBackOff"),
            reason="ImagePullBackOff",
            client=client,
            debouncer=Debouncer(threshold=1),
            policy=policy,
            breaker=breaker,
            now=NOW + timedelta(minutes=offset),
        )
    assert len(client.rollbacks) == 2
    assert client.audits[-1].action == Action.ESCALATE


def test_bad_image_demo_rolls_back() -> None:
    """demo/manifests/bad-image: ImagePullBackOff → rollback to last healthy RS."""
    client = RecordingClusterClient(
        workload_name="storefront",
        logs="Failed to pull image nginx:does-not-exist",
        revisions=[_healthy_revision("storefront-nginx-1-25")],
    )
    action = handle_failure(
        _pod(reason="ImagePullBackOff"),
        reason="ImagePullBackOff",
        client=client,
        debouncer=Debouncer(threshold=1),
        policy=_enforce(Action.ROLLBACK, Action.RESTART),
        now=NOW,
    )
    assert action == Action.ROLLBACK
    assert client.rollbacks == [("demo", "storefront", "storefront-nginx-1-25")]


def test_real_bug_demo_escalates_instead_of_remediating() -> None:
    """demo/manifests/real-bug: genuine app crash → escalate, never rollback/restart."""
    client = RecordingClusterClient(
        workload_name="payments",
        logs="Traceback (most recent call last):\nValueError: boom",
        revisions=[_healthy_revision("payments-healthy")],
    )
    action = handle_failure(
        _pod(reason="CrashLoopBackOff"),
        reason="CrashLoopBackOff",
        client=client,
        debouncer=Debouncer(threshold=1),
        policy=_enforce(Action.ROLLBACK, Action.RESTART),
        now=NOW,
    )
    assert action == Action.ESCALATE
    assert client.rollbacks == []
    assert client.restarts == []
    assert client.audits[0].classification == Action.ESCALATE
    assert client.audits[0].outcome == "escalated"


def test_diagnose_falls_back_to_current_logs_when_previous_empty() -> None:
    """Containers that print and exit 1 often have no previous terminated instance."""
    client = RecordingClusterClient(logs="", current=REAL_BUG_TRACEBACK, workload_name="payments")
    diagnosis = diagnose(
        _real_bug_live_pod(include_traceback_in_args=False),
        client=client,
        reason="CrashLoopBackOff",
    )
    assert "traceback (most recent call last)" in diagnosis.compressed_logs.lower()
    assert classify_failure(diagnosis) == Action.ESCALATE


def test_diagnose_uses_pod_body_when_log_apis_are_empty() -> None:
    """Live kind path: previous_logs is empty, traceback is on the container args."""
    diagnosis = diagnose(
        _real_bug_live_pod(),
        client=NullClusterClient(),
        reason="CrashLoopBackOff",
    )
    assert "traceback (most recent call last)" in diagnosis.compressed_logs.lower()
    assert classify_failure(diagnosis) == Action.ESCALATE


def test_diagnose_logs_retrieved_evidence_at_debug(
    caplog: logging.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="impactgate.controller")
    diagnose(
        _real_bug_live_pod(),
        client=RecordingClusterClient(logs="", current=REAL_BUG_TRACEBACK),
        reason="CrashLoopBackOff",
    )
    messages = [rec.message for rec in caplog.records if rec.levelno == logging.DEBUG]
    assert any("previous_empty=True" in msg for msg in messages)
    assert any("Traceback (most recent call last)" in msg for msg in messages)


def test_real_bug_live_pod_escalates_with_empty_previous_logs() -> None:
    """Repro: CrashLoopBackOff + empty previous_logs must not default to restart."""
    client = RecordingClusterClient(
        workload_name="payments",
        logs="",
        current=REAL_BUG_TRACEBACK,
        revisions=[_healthy_revision("payments-healthy")],
    )
    action = handle_failure(
        _real_bug_live_pod(include_traceback_in_args=False),
        reason="CrashLoopBackOff",
        client=client,
        debouncer=Debouncer(threshold=1),
        policy=default_policy(),
        now=NOW,
    )
    assert action == Action.ESCALATE
    assert client.restarts == []
    assert client.audits[0].classification == Action.ESCALATE


def test_crashloop_without_traceback_still_restarts() -> None:
    client = RecordingClusterClient(logs="", current="", workload_name="payments")
    diagnosis = diagnose(
        _real_bug_live_pod(include_traceback_in_args=False),
        client=client,
        reason="CrashLoopBackOff",
    )
    assert classify_failure(diagnosis) == Action.RESTART


def test_workload_from_pod_strips_replicaset_hash() -> None:
    assert workload_from_pod(_real_bug_live_pod()) == "payments"


def test_workload_from_pod_resolves_kopf_body() -> None:
    import kopf

    body = kopf.Body(_real_bug_live_pod())
    assert not isinstance(body, dict)
    assert workload_from_pod(body) == "payments"


def test_extract_runtime_evidence_includes_command_args() -> None:
    evidence = extract_runtime_evidence(_real_bug_live_pod())
    assert "Traceback (most recent call last)" in evidence
    assert "exitCode: 1" in evidence


def test_kubernetes_client_log_methods_delegate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []

    def fake_read(namespace: str, name: str, *, previous: bool) -> str:
        del namespace, name
        seen.append(previous)
        return "Traceback (most recent call last):" if not previous else ""

    monkeypatch.setattr("impactgate.controller.watcher.read_pod_logs", fake_read)
    client = KubernetesClusterClient()
    assert client.previous_logs("demo", "payments-x") == ""
    assert client.current_logs("demo", "payments-x") == "Traceback (most recent call last):"
    assert seen == [True, False]


TRACEBACK_BYTES = b"Traceback (most recent call last):\nValueError: boom\n"
TRACEBACK_TEXT = "Traceback (most recent call last):\nValueError: boom\n"


def _install_fake_kubernetes(monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
    def load_incluster_config() -> None:
        raise RuntimeError("no in-cluster config")

    fake_api = SimpleNamespace(
        read_namespaced_pod_log=lambda **_: payload,
    )
    fake_client = SimpleNamespace(CoreV1Api=lambda: fake_api)
    fake_config = SimpleNamespace(
        load_incluster_config=load_incluster_config,
        load_kube_config=lambda: None,
    )
    fake_mod = ModuleType("kubernetes")
    setattr(fake_mod, "client", fake_client)
    setattr(fake_mod, "config", fake_config)
    monkeypatch.setitem(sys.modules, "kubernetes", fake_mod)


def test_decode_log_text_turns_bytes_into_str() -> None:
    decoded = _decode_log_text(TRACEBACK_BYTES)
    assert isinstance(decoded, str)
    assert decoded == TRACEBACK_TEXT
    assert decoded.startswith("Traceback")
    assert "\n" in decoded
    assert "b'" not in decoded


def test_logs_via_kubernetes_decodes_bytes_to_str(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_kubernetes(monkeypatch, TRACEBACK_BYTES)
    text = _logs_via_kubernetes("demo", "payments-x", previous=False)
    assert type(text) is str
    assert text == TRACEBACK_TEXT
    assert "\\n" not in text


def test_log_readers_always_return_str(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_kubernetes(monkeypatch, TRACEBACK_BYTES)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setattr(
        "impactgate.controller.watcher.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=TRACEBACK_BYTES),
    )
    readers = (_logs_via_kubernetes, _logs_via_incluster, _logs_via_kubectl)
    for reader in readers:
        result = reader("demo", "payments-x", previous=False)
        assert type(result) is str, reader.__name__


def test_read_pod_logs_decodes_bytes_from_first_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_kubernetes(monkeypatch, TRACEBACK_BYTES)
    text = read_pod_logs("demo", "payments-x", previous=False)
    assert type(text) is str
    assert text == TRACEBACK_TEXT
    diagnosis = diagnose(
        _real_bug_live_pod(include_traceback_in_args=False),
        client=KubernetesClusterClient(),
        reason="CrashLoopBackOff",
    )
    assert type(diagnosis.compressed_logs) is str
    assert "Traceback (most recent call last)" in diagnosis.compressed_logs
    assert "b'" not in diagnosis.compressed_logs
    assert classify_failure(diagnosis) == Action.ESCALATE


def test_oom_bumps_memory_when_allowed() -> None:
    client = RecordingClusterClient(
        workload_name="storefront",
        logs="lastState: OOMKilled",
        memory_limit="256Mi",
        revisions=[_healthy_revision()],
    )
    action = handle_failure(
        _pod(reason="CrashLoopBackOff", oom=True),
        reason="OOMKilled",
        client=client,
        debouncer=Debouncer(threshold=1),
        policy=_enforce(Action.BUMP_MEMORY),
        now=NOW,
    )
    assert action == Action.BUMP_MEMORY
    assert client.memory_bumps == [("demo", "storefront", "384Mi")]


def test_kopf_testing_utilities_are_available() -> None:
    import kopf
    from kopf.testing import KopfRunner

    from impactgate.controller import watcher

    assert KopfRunner is not None
    assert kopf.get_default_registry() is not None
    assert watcher.handle_failure is not None
    watching = {handler.fn for handler in kopf.get_default_registry()._watching.get_all_handlers()}
    assert watcher.handle_policy_event in watching
    assert watcher.handle_pod_event in watching
