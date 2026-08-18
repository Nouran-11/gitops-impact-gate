"""kopf handlers, debounce, diagnosis, and dry-run logging."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from impactgate.controller.actions import (
    Action,
    AuditRecord,
    CircuitBreaker,
    ClusterClient,
    Diagnosis,
    ReplicaSetRevision,
    classify_failure,
    execute_action,
)
from impactgate.controller.policy import RemediationPolicy, default_policy
from impactgate.metrics import REGISTRY

LOGGER = logging.getLogger("impactgate.controller")
MANAGED_LABEL = "impactgate.io/managed"
WATCH_REASONS = {
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "CreateContainerConfigError",
    "OOMKilled",
    "FailedScheduling",
    "Unhealthy",
    "BackOff",
}


@dataclass
class Debouncer:
    threshold: int = 3
    window: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    _hits: dict[str, list[datetime]] = field(default_factory=lambda: defaultdict(list))

    def record(self, key: str, at: datetime | None = None) -> bool:
        """Return True once N failures land inside the window."""
        now = at or datetime.now(UTC)
        recent = [stamp for stamp in self._hits[key] if now - stamp <= self.window]
        recent.append(now)
        self._hits[key] = recent
        return len(recent) >= self.threshold


class NullClusterClient:
    def previous_logs(self, namespace: str, pod: str) -> str:
        del namespace, pod
        return ""

    def pod_events(self, namespace: str, pod: str) -> list[str]:
        del namespace, pod
        return []

    def owning_workload(self, namespace: str, pod: Mapping[str, Any]) -> str:
        del namespace
        return str((pod.get("metadata") or {}).get("name") or "unknown")

    def replicaset_history(self, namespace: str, workload: str) -> list[str]:
        del namespace, workload
        return []

    def list_revisions(self, namespace: str, workload: str) -> list[ReplicaSetRevision]:
        del namespace, workload
        return []

    def rollback(self, namespace: str, workload: str, revision: str) -> str:
        del namespace, workload
        return f"rolled-back:{revision}"

    def current_memory_limit(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "256Mi"

    def bump_memory(self, namespace: str, workload: str, new_limit: str) -> str:
        del namespace, workload
        return f"memory-bumped:{new_limit}"

    def restart(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "restarted"

    def scale_out(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "scaled-out"

    def emit_event(self, namespace: str, workload: str, message: str) -> None:
        del namespace, workload, message

    def record_audit(self, record: AuditRecord) -> None:
        del record


def compress_logs(raw: str, *, max_chars: int = 4000) -> str:
    """Collapse consecutive duplicate lines and cap length. Shared with CI diagnosis."""
    if not raw:
        return ""
    collapsed: list[str] = []
    previous = None
    repeat = 0
    for line in raw.splitlines():
        stripped = line.rstrip()
        if stripped == previous:
            repeat += 1
            continue
        if repeat:
            collapsed.append(f"... repeated {repeat} more times")
            repeat = 0
        collapsed.append(stripped)
        previous = stripped
    if repeat:
        collapsed.append(f"... repeated {repeat} more times")
    text = "\n".join(collapsed)
    if len(text) > max_chars:
        return text[: max_chars - 16] + "\n...[truncated]"
    return text


def extract_waiting_reason(pod: Mapping[str, Any]) -> str | None:
    status_obj = pod.get("status")
    status = status_obj if isinstance(status_obj, dict) else {}
    for key in ("containerStatuses", "initContainerStatuses"):
        for container in _as_list(status.get(key)):
            if not isinstance(container, dict):
                continue
            state_obj = container.get("state")
            state = state_obj if isinstance(state_obj, dict) else {}
            waiting_obj = state.get("waiting")
            waiting = waiting_obj if isinstance(waiting_obj, dict) else {}
            reason = waiting.get("reason")
            if isinstance(reason, str) and reason in WATCH_REASONS:
                return reason
            last_obj = container.get("lastState")
            last_state = last_obj if isinstance(last_obj, dict) else {}
            terminated_obj = last_state.get("terminated")
            terminated = terminated_obj if isinstance(terminated_obj, dict) else {}
            last_reason = terminated.get("reason")
            if isinstance(last_reason, str) and last_reason in WATCH_REASONS:
                return last_reason
    phase_reason = status.get("reason")
    if isinstance(phase_reason, str) and phase_reason in WATCH_REASONS:
        return phase_reason
    return None


def is_managed(pod: Mapping[str, Any]) -> bool:
    labels = (pod.get("metadata") or {}).get("labels") or {}
    return str(labels.get(MANAGED_LABEL, "")).lower() == "true"


def diagnose(
    pod: Mapping[str, Any],
    *,
    client: ClusterClient,
    reason: str,
) -> Diagnosis:
    metadata = pod.get("metadata") or {}
    namespace = str(metadata.get("namespace") or "default")
    name = str(metadata.get("name") or "unknown")
    logs = client.previous_logs(namespace, name)
    events = client.pod_events(namespace, name)
    workload = client.owning_workload(namespace, pod)
    history = client.replicaset_history(namespace, workload)
    return Diagnosis(
        namespace=namespace,
        pod=name,
        workload=workload,
        reason=reason,
        compressed_logs=compress_logs(logs),
        events=[*events, *history],
        managed=is_managed(pod),
    )


def handle_failure(
    pod: Mapping[str, Any],
    *,
    reason: str,
    client: ClusterClient,
    debouncer: Debouncer,
    policy: RemediationPolicy | None = None,
    breaker: CircuitBreaker | None = None,
    logger: logging.Logger = LOGGER,
    now: datetime | None = None,
) -> Action | None:
    """Diagnose, debounce, classify, apply guardrails, and act or dry-run."""
    if not is_managed(pod):
        logger.info("skipping unmanaged pod %s", (pod.get("metadata") or {}).get("name"))
        return None
    diagnosis = diagnose(pod, client=client, reason=reason)
    key = f"{diagnosis.namespace}/{diagnosis.workload}"
    REGISTRY.note_detection(key, at=now)
    if not debouncer.record(key, at=now):
        logger.info("debouncing %s after %s", key, reason)
        return None
    action = classify_failure(diagnosis)
    effective = policy if policy is not None else default_policy()
    record = execute_action(
        diagnosis,
        action,
        effective,
        client,
        breaker=breaker,
        now=now,
        logger=logger,
    )
    # Dry-run reports the classified action (what we would do). Enforce returns
    # the action after guardrails, which may be ESCALATE.
    return record.classification if record.dry_run else record.action


def is_pod_ready(pod: Mapping[str, Any]) -> bool:
    status_obj = pod.get("status")
    status = status_obj if isinstance(status_obj, dict) else {}
    containers = _as_list(status.get("containerStatuses"))
    if not containers:
        return False
    return all(isinstance(item, dict) and item.get("ready") is True for item in containers)


def maybe_record_recovery(
    pod: Mapping[str, Any],
    *,
    client: ClusterClient,
    now: datetime | None = None,
) -> float | None:
    """Stop the MTTR timer once every container on a managed pod is ready."""
    if not is_managed(pod) or not is_pod_ready(pod):
        return None
    metadata = pod.get("metadata") or {}
    namespace = str(metadata.get("namespace") or "default")
    workload = client.owning_workload(namespace, pod)
    return REGISTRY.note_recovery(f"{namespace}/{workload}", at=now)


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _register_kopf() -> None:
    try:
        import kopf
    except ImportError:
        return

    state: dict[str, object] = {
        "debouncer": Debouncer(),
        "client": NullClusterClient(),
        "breaker": CircuitBreaker(),
    }

    @kopf.on.event("", "v1", "pods")
    def on_pod_event(body: Mapping[str, Any], **_: object) -> None:
        client = state["client"]
        debouncer = state["debouncer"]
        breaker = state["breaker"]
        assert isinstance(client, NullClusterClient)
        assert isinstance(debouncer, Debouncer)
        assert isinstance(breaker, CircuitBreaker)
        reason = extract_waiting_reason(body)
        if reason is None:
            maybe_record_recovery(body, client=client)
            return
        handle_failure(
            body,
            reason=reason,
            client=client,
            debouncer=debouncer,
            breaker=breaker,
        )


_register_kopf()
