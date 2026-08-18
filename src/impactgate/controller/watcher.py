"""kopf handlers, debounce, diagnosis, and dry-run logging."""

from __future__ import annotations

import logging
import os
import subprocess
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
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


class NullClusterClient:
    def previous_logs(self, namespace: str, pod: str) -> str:
        del namespace, pod
        return ""

    def current_logs(self, namespace: str, pod: str) -> str:
        del namespace, pod
        return ""

    def pod_events(self, namespace: str, pod: str) -> list[str]:
        del namespace, pod
        return []

    def owning_workload(self, namespace: str, pod: Mapping[str, Any]) -> str:
        del namespace
        return workload_from_pod(pod)

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


class KubernetesClusterClient(NullClusterClient):
    """Live cluster access. Log fetches try previous, then the current container."""

    def previous_logs(self, namespace: str, pod: str) -> str:
        return read_pod_logs(namespace, pod, previous=True)

    def current_logs(self, namespace: str, pod: str) -> str:
        return read_pod_logs(namespace, pod, previous=False)


def extract_runtime_evidence(pod: Mapping[str, Any]) -> str:
    """Evidence kopf already has on the pod body — used when log APIs are empty.

    Containers that print a traceback and exit 1 often have no *previous*
    instance, so ``kubectl logs --previous`` is empty. Status messages and the
    container command/args still sit on the object and must reach the classifier.
    """
    lines: list[str] = []
    spec_obj = pod.get("spec")
    spec = spec_obj if isinstance(spec_obj, dict) else {}
    for container in _as_list(spec.get("containers")):
        if not isinstance(container, dict):
            continue
        name = str(container.get("name") or "container")
        command = [str(item) for item in _as_list(container.get("command"))]
        args = [str(item) for item in _as_list(container.get("args"))]
        joined = " ".join([*command, *args]).strip()
        if joined:
            lines.append(f"container {name} command: {joined}")
    status_obj = pod.get("status")
    status = status_obj if isinstance(status_obj, dict) else {}
    for key in ("containerStatuses", "initContainerStatuses"):
        for container in _as_list(status.get(key)):
            if not isinstance(container, dict):
                continue
            name = str(container.get("name") or "container")
            for state_name in ("state", "lastState"):
                state_obj = container.get(state_name)
                state = state_obj if isinstance(state_obj, dict) else {}
                waiting_obj = state.get("waiting")
                waiting = waiting_obj if isinstance(waiting_obj, dict) else {}
                terminated_obj = state.get("terminated")
                terminated = terminated_obj if isinstance(terminated_obj, dict) else {}
                message = waiting.get("message") or terminated.get("message")
                reason = waiting.get("reason") or terminated.get("reason")
                exit_code = terminated.get("exitCode")
                if reason:
                    lines.append(f"container {name} {state_name} reason: {reason}")
                if exit_code is not None:
                    lines.append(f"container {name} {state_name} exitCode: {exit_code}")
                if message:
                    lines.append(f"container {name} {state_name} message: {message}")
    return "\n".join(lines)


def read_pod_logs(namespace: str, name: str, *, previous: bool) -> str:
    """Fetch container logs. Empty is normal when a container exits instead of crashing."""
    for reader in (_logs_via_kubernetes, _logs_via_incluster, _logs_via_kubectl):
        try:
            text = reader(namespace, name, previous=previous)
        except Exception:
            LOGGER.debug(
                "log reader %s failed for %s/%s",
                reader.__name__,
                namespace,
                name,
                exc_info=True,
            )
            continue
        if text.strip():
            return text
    return ""


def _logs_via_kubernetes(namespace: str, name: str, *, previous: bool) -> str:
    from kubernetes import client, config  # type: ignore[import-not-found]

    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    api = client.CoreV1Api()
    text = api.read_namespaced_pod_log(
        name=name,
        namespace=namespace,
        previous=previous,
        timestamps=False,
        tail_lines=400,
    )
    return text if isinstance(text, str) else ""


def _logs_via_incluster(namespace: str, name: str, *, previous: bool) -> str:
    host = os.environ.get("KUBERNETES_SERVICE_HOST")
    token_file = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if not host or not token_file.is_file():
        return ""
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    token = token_file.read_text(encoding="utf-8").strip()
    ca = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    import httpx

    params: dict[str, str] = {"tailLines": "400"}
    if previous:
        params["previous"] = "true"
    url = f"https://{host}:{port}/api/v1/namespaces/{namespace}/pods/{name}/log"
    verify: str | bool = str(ca) if ca.is_file() else False
    with httpx.Client(verify=verify, timeout=10.0) as http:
        response = http.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
    if response.status_code == 200:
        return response.text
    return ""


def _logs_via_kubectl(namespace: str, name: str, *, previous: bool) -> str:
    cmd = [
        "kubectl",
        "logs",
        "-n",
        namespace,
        name,
        "--tail=400",
        "--all-containers=true",
    ]
    if previous:
        cmd.append("--previous")
    completed = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    if completed.returncode == 0:
        return completed.stdout or ""
    return ""


def workload_from_pod(pod: Mapping[str, Any]) -> str:
    """Deployment/StatefulSet/DaemonSet name, walking ReplicaSet ownerReferences."""
    metadata = pod.get("metadata") or {}
    owners = metadata.get("ownerReferences") or []
    if isinstance(owners, list):
        for owner in owners:
            if not isinstance(owner, dict):
                continue
            kind = owner.get("kind")
            name = owner.get("name")
            if not isinstance(name, str) or not name:
                continue
            if kind in {"Deployment", "StatefulSet", "DaemonSet"}:
                return name
            if kind == "ReplicaSet":
                return name.rsplit("-", 1)[0] if "-" in name else name
    return str(metadata.get("name") or "unknown")


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
    logger: logging.Logger = LOGGER,
) -> Diagnosis:
    metadata = pod.get("metadata") or {}
    namespace = str(metadata.get("namespace") or "default")
    name = str(metadata.get("name") or "unknown")
    previous = client.previous_logs(namespace, name)
    # Containers that print and exit (real-bug demo) often have no previous
    # instance; the traceback is on the current/last terminated container.
    current = "" if previous.strip() else client.current_logs(namespace, name)
    inline = extract_runtime_evidence(pod)
    combined = "\n".join(part for part in (previous, current, inline) if part.strip())
    events = client.pod_events(namespace, name)
    workload = client.owning_workload(namespace, pod)
    history = client.replicaset_history(namespace, workload)
    compressed = compress_logs(combined)
    logger.debug(
        "diagnose %s/%s reason=%s previous_empty=%s current_empty=%s "
        "inline_chars=%d evidence=%s",
        namespace,
        name,
        reason,
        not previous.strip(),
        not current.strip(),
        len(inline),
        compressed or "<empty>",
    )
    return Diagnosis(
        namespace=namespace,
        pod=name,
        workload=workload,
        reason=reason,
        compressed_logs=compressed,
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
    diagnosis = diagnose(pod, client=client, reason=reason, logger=logger)
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


RUNTIME = ControllerRuntime(client=KubernetesClusterClient())


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
    """Serve Prometheus text at /metrics for the controller process."""
    from impactgate.config import load_settings

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
