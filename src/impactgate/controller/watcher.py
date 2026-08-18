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
    CircuitBreaker,
    ClusterClient,
    Diagnosis,
    classify_failure,
    execute_action,
)
from impactgate.controller.cluster import NullClusterClient, attach_kubernetes_client
from impactgate.controller.policy import RemediationPolicy, default_policy, policy_from_crd
from impactgate.metrics import REGISTRY, start_http_server

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


class PolicyCache:
    """Namespaced RemediationPolicy objects as seen on the cluster."""

    def __init__(self) -> None:
        self._policies: dict[tuple[str, str], RemediationPolicy] = {}
        self._missing_warned: set[str] = set()

    def upsert(self, namespace: str, name: str, spec: Mapping[str, object]) -> RemediationPolicy:
        policy = policy_from_crd(dict(spec))
        self._policies[(namespace, name)] = policy
        self._missing_warned.discard(namespace)
        return policy

    def delete(self, namespace: str, name: str) -> None:
        self._policies.pop((namespace, name), None)

    def for_namespace(self, namespace: str) -> RemediationPolicy:
        named = self._policies.get((namespace, "default"))
        if named is not None:
            return named
        matches = [policy for (ns, _name), policy in self._policies.items() if ns == namespace]
        if len(matches) == 1:
            return matches[0]
        if namespace not in self._missing_warned:
            self._missing_warned.add(namespace)
            LOGGER.warning(
                "no RemediationPolicy in namespace %s; using dry-run with no allowed actions",
                namespace,
            )
        return default_policy()


@dataclass
class ControllerRuntime:
    """In-process stand-in for the kopf watchers. Tests feed cluster objects here."""

    debouncer: Debouncer = field(default_factory=Debouncer)
    client: ClusterClient = field(default_factory=lambda: NullClusterClient())
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    policies: PolicyCache = field(default_factory=PolicyCache)
    logger: logging.Logger = LOGGER

    def ingest_policy(self, body: Mapping[str, Any], *, deleted: bool = False) -> None:
        metadata = body.get("metadata") or {}
        namespace = str(metadata.get("namespace") or "default")
        name = str(metadata.get("name") or "default")
        if deleted:
            self.policies.delete(namespace, name)
            self.logger.info("dropped RemediationPolicy %s/%s", namespace, name)
            return
        spec_obj = body.get("spec") or {}
        spec = spec_obj if isinstance(spec_obj, dict) else {}
        policy = self.policies.upsert(namespace, name, spec)
        self.logger.info(
            "loaded RemediationPolicy %s/%s mode=%s allowed=%s",
            namespace,
            name,
            policy.mode,
            [item.value for item in policy.allowed_actions],
        )

    def ingest_pod(self, body: Mapping[str, Any], *, now: datetime | None = None) -> Action | None:
        reason = extract_waiting_reason(body)
        if reason is None:
            maybe_record_recovery(body, client=self.client, now=now)
            return None
        metadata = body.get("metadata") or {}
        namespace = str(metadata.get("namespace") or "default")
        return handle_failure(
            body,
            reason=reason,
            client=self.client,
            debouncer=self.debouncer,
            policy=self.policies.for_namespace(namespace),
            breaker=self.breaker,
            logger=self.logger,
            now=now,
        )


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
    """True only when the *pod* carries impactgate.io/managed=true.

    Kubernetes copies labels from spec.template.metadata.labels, not from the
    owning Deployment's metadata.labels.
    """
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


RUNTIME = ControllerRuntime()


def reset_runtime(
    *,
    client: ClusterClient | None = None,
    debouncer: Debouncer | None = None,
    breaker: CircuitBreaker | None = None,
) -> ControllerRuntime:
    """Replace the process-wide runtime. Used by tests between scenarios."""
    global RUNTIME
    RUNTIME = ControllerRuntime(
        debouncer=debouncer if debouncer is not None else Debouncer(),
        client=client if client is not None else NullClusterClient(),
        breaker=breaker if breaker is not None else CircuitBreaker(),
        policies=PolicyCache(),
    )
    return RUNTIME


def handle_policy_event(
    body: Mapping[str, Any],
    type: str | None = None,
    **_: object,
) -> None:
    """kopf: watch RemediationPolicy and cache the spec for the pod's namespace."""
    RUNTIME.ingest_policy(body, deleted=type == "DELETED")


def handle_pod_event(body: Mapping[str, Any], **_: object) -> Action | None:
    """kopf: watch Pods and remediate using the policy for that namespace."""
    return RUNTIME.ingest_pod(body)


def handle_startup(**_: object) -> int:
    """Serve Prometheus text at /metrics and attach a live cluster client."""
    from impactgate.config import load_settings

    attach_kubernetes_client(RUNTIME)
    settings = load_settings()
    port = start_http_server(settings.metrics_port)
    LOGGER.info("serving /metrics on port %s", port)
    return port


_KOPF_REGISTERED = False


def _register_kopf() -> None:
    global _KOPF_REGISTERED
    if _KOPF_REGISTERED:
        return
    try:
        import kopf
    except ImportError:
        return

    kopf.on.startup()(handle_startup)
    kopf.on.event("impactgate.io", "v1", "remediationpolicies")(handle_policy_event)
    kopf.on.event("", "v1", "pods")(handle_pod_event)
    _KOPF_REGISTERED = True


_register_kopf()
