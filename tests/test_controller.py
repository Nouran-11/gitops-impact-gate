from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

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
from impactgate.controller.policy import RemediationPolicy, default_policy, policy_from_crd
from impactgate.controller.watcher import (
    Debouncer,
    NullClusterClient,
    compress_logs,
    extract_waiting_reason,
    handle_failure,
    is_managed,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


@dataclass
class RecordingClusterClient:
    logs: str = ""
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
