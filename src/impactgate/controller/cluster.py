"""Kubernetes API client for controller remediation. NullClusterClient is the test double."""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from impactgate.controller.actions import AuditRecord, ClusterClient, ReplicaSetRevision

LOGGER = logging.getLogger("impactgate.controller")
READY_ANNOTATION = "impactgate.io/fully-ready-since"
AUDIT_ANNOTATION = "impactgate.io/last-audit"
RESTART_ANNOTATION = "kubectl.kubernetes.io/restartedAt"
REPLICA_CEILING = 32
WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}


class HasClient(Protocol):
    client: ClusterClient


class NullClusterClient:
    """In-memory double. Does not touch a cluster; mutations return canned strings."""

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

    def restart(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "restarted"

    def current_memory_limit(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "256Mi"

    def bump_memory(self, namespace: str, workload: str, new_limit: str) -> str:
        del namespace, workload
        return f"memory-bumped:{new_limit}"

    def scale_out(self, namespace: str, workload: str) -> str:
        del namespace, workload
        return "scaled-out"

    def emit_event(self, namespace: str, workload: str, message: str) -> None:
        del namespace, workload, message

    def record_audit(self, record: AuditRecord) -> None:
        del record


class KubernetesClusterClient:
    """Mutates Deployments and ReplicaSets through the Kubernetes API."""

    replica_ceiling: int = REPLICA_CEILING

    def __init__(
        self,
        *,
        core: Any | None = None,
        apps: Any | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._core: Any = core
        self._apps: Any = apps
        self._injected = core is not None and apps is not None
        self._clock = clock or (lambda: datetime.now(UTC))
        self.audits: list[AuditRecord] = []

    def _ensure_apis(self) -> tuple[Any, Any]:
        if self._core is None or self._apps is None:
            self._core, self._apps = _load_kubernetes_apis()
        return self._core, self._apps

    def previous_logs(self, namespace: str, pod: str) -> str:
        return self._read_logs(namespace, pod, previous=True)

    def current_logs(self, namespace: str, pod: str) -> str:
        return self._read_logs(namespace, pod, previous=False)

    def _read_logs(self, namespace: str, pod: str, *, previous: bool) -> str:
        if not self._injected:
            from impactgate.controller.watcher import read_pod_logs

            return read_pod_logs(namespace, pod, previous=previous)
        try:
            logs = self._core.read_namespaced_pod_log(
                pod, namespace, previous=previous, tail_lines=200
            )
        except Exception:
            if previous:
                try:
                    logs = self._core.read_namespaced_pod_log(pod, namespace, tail_lines=200)
                except Exception as exc:
                    LOGGER.warning("pod logs unavailable for %s/%s: %s", namespace, pod, exc)
                    return ""
            else:
                return ""
        return _decode_log_text(logs)

    def pod_events(self, namespace: str, pod: str) -> list[str]:
        try:
            self._ensure_apis()
            listing = self._core.list_namespaced_event(
                namespace,
                field_selector=f"involvedObject.name={pod}",
            )
        except Exception as exc:
            LOGGER.warning("pod events unavailable for %s/%s: %s", namespace, pod, exc)
            return []
        lines: list[str] = []
        for item in _list_items(listing):
            reason = _pick(item, "reason") or ""
            message = _pick(item, "message") or ""
            lines.append(f"{reason}: {message}".strip(": "))
        return lines

    def owning_workload(self, namespace: str, pod: Mapping[str, Any]) -> str:
        meta = _metadata(pod)
        for owner in _owners(meta):
            kind = str(owner.get("kind") or "")
            name = str(owner.get("name") or "")
            if kind in WORKLOAD_KINDS and name:
                return name
            if kind == "ReplicaSet" and name:
                try:
                    self._ensure_apis()
                    rs = _plain(self._apps.read_namespaced_replica_set(name, namespace))
                except Exception:
                    return _strip_hash(name)
                for rs_owner in _owners(_metadata(rs)):
                    if str(rs_owner.get("kind") or "") in WORKLOAD_KINDS and rs_owner.get("name"):
                        return str(rs_owner["name"])
                return _strip_hash(name)
        return str(meta.get("name") or "unknown")

    def replicaset_history(self, namespace: str, workload: str) -> list[str]:
        return [item.name for item in self.list_revisions(namespace, workload)]

    def list_revisions(self, namespace: str, workload: str) -> list[ReplicaSetRevision]:
        try:
            self._ensure_apis()
            listing = self._apps.list_namespaced_replica_set(namespace)
        except Exception as exc:
            LOGGER.warning("replica sets unavailable in %s: %s", namespace, exc)
            return []
        revisions: list[ReplicaSetRevision] = []
        for rs in _list_items(listing):
            if not _owned_by_workload(rs, workload):
                continue
            meta = _metadata(rs)
            name = str(meta.get("name") or "")
            spec = _mapping(rs.get("spec"))
            status = _mapping(rs.get("status"))
            desired = int(spec.get("replicas") or 0)
            ready = int(_pick(status, "readyReplicas", "ready_replicas") or 0)
            ready_since = self._record_ready_since(namespace, name, rs, desired, ready)
            revisions.append(
                ReplicaSetRevision(
                    name=name,
                    desired=desired,
                    ready=ready,
                    ready_since=ready_since,
                )
            )
        return revisions

    def rollback(self, namespace: str, workload: str, revision: str) -> str:
        self._ensure_apis()
        rs = _plain(self._apps.read_namespaced_replica_set(revision, namespace))
        template = copy.deepcopy(_mapping(_mapping(rs.get("spec")).get("template")))
        if not template:
            msg = f"rolled-back:{revision}: missing template"
            LOGGER.warning(msg)
            return msg
        labels = dict(_mapping(_mapping(template.get("metadata")).get("labels")))
        labels.pop("pod-template-hash", None)
        template.setdefault("metadata", {})
        if isinstance(template["metadata"], dict):
            template["metadata"]["labels"] = labels
        self._apps.patch_namespaced_deployment(
            workload,
            namespace,
            {"spec": {"template": template}},
        )
        return f"rolled-back:{revision}"

    def restart(self, namespace: str, workload: str) -> str:
        self._ensure_apis()
        stamp = _format_time(self._clock())
        self._apps.patch_namespaced_deployment(
            workload,
            namespace,
            {
                "spec": {
                    "template": {
                        "metadata": {"annotations": {RESTART_ANNOTATION: stamp}},
                    }
                }
            },
        )
        return "restarted"

    def current_memory_limit(self, namespace: str, workload: str) -> str:
        self._ensure_apis()
        deploy = _plain(self._apps.read_namespaced_deployment(workload, namespace))
        for container in _containers(deploy):
            resources = _mapping(container.get("resources"))
            limits = _mapping(resources.get("limits"))
            memory = limits.get("memory")
            if memory:
                return str(memory)
        return "256Mi"

    def bump_memory(self, namespace: str, workload: str, new_limit: str) -> str:
        self._ensure_apis()
        deploy = _plain(self._apps.read_namespaced_deployment(workload, namespace))
        patched: list[dict[str, Any]] = []
        for container in _containers(deploy):
            item = copy.deepcopy(container)
            resources = dict(_mapping(item.get("resources")))
            limits = dict(_mapping(resources.get("limits")))
            limits["memory"] = new_limit
            resources["limits"] = limits
            item["resources"] = resources
            patched.append(item)
        self._apps.patch_namespaced_deployment(
            workload,
            namespace,
            {"spec": {"template": {"spec": {"containers": patched}}}},
        )
        return f"memory-bumped:{new_limit}"

    def scale_out(self, namespace: str, workload: str) -> str:
        self._ensure_apis()
        deploy = _plain(self._apps.read_namespaced_deployment(workload, namespace))
        replicas = int(_mapping(deploy.get("spec")).get("replicas") or 1)
        new_replicas = min(replicas + 1, self.replica_ceiling)
        self._apps.patch_namespaced_deployment(
            workload,
            namespace,
            {"spec": {"replicas": new_replicas}},
        )
        return f"scaled-out:{new_replicas}"

    def emit_event(self, namespace: str, workload: str, message: str) -> None:
        self._ensure_apis()
        stamp = _format_time(self._clock())
        body = {
            "metadata": {"generateName": "impactgate-", "namespace": namespace},
            "involvedObject": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": workload,
                "namespace": namespace,
            },
            "reason": "ImpactGateRemediation",
            "message": message,
            "type": "Normal",
            "source": {"component": "impactgate"},
            "firstTimestamp": stamp,
            "lastTimestamp": stamp,
            "count": 1,
        }
        try:
            self._core.create_namespaced_event(namespace, body)
        except Exception as exc:
            LOGGER.warning("failed to emit event on %s/%s: %s", namespace, workload, exc)

    def record_audit(self, record: AuditRecord) -> None:
        self.audits.append(record)
        self._ensure_apis()
        namespace, _, name = record.workload.partition("/")
        if not name:
            namespace, name = "default", record.workload
        payload = json.dumps(record.model_dump(mode="json"), default=str)
        try:
            self._apps.patch_namespaced_deployment(
                name,
                namespace,
                {"metadata": {"annotations": {AUDIT_ANNOTATION: payload}}},
            )
        except Exception as exc:
            LOGGER.warning("failed to persist audit on %s: %s", record.workload, exc)

    def _record_ready_since(
        self,
        namespace: str,
        name: str,
        rs: Mapping[str, Any],
        desired: int,
        ready: int,
    ) -> datetime | None:
        annotations = dict(_mapping(_metadata(rs).get("annotations")))
        existing = annotations.get(READY_ANNOTATION)
        if desired <= 0 or ready != desired:
            if existing:
                self._patch_rs_annotation(namespace, name, "")
            return None
        parsed = _parse_time(str(existing)) if existing else None
        if parsed is not None:
            return parsed
        now = self._clock()
        self._patch_rs_annotation(namespace, name, _format_time(now))
        return now

    def _patch_rs_annotation(self, namespace: str, name: str, value: str) -> None:
        self._ensure_apis()
        try:
            self._apps.patch_namespaced_replica_set(
                name,
                namespace,
                {"metadata": {"annotations": {READY_ANNOTATION: value}}},
            )
        except Exception as exc:
            LOGGER.warning("failed to stamp ReplicaSet %s/%s: %s", namespace, name, exc)


def attach_kubernetes_client(runtime: HasClient) -> ClusterClient:
    """Replace NullClusterClient with a live API client when kubeconfig is available."""
    if type(runtime.client) is not NullClusterClient:
        return runtime.client
    try:
        runtime.client = KubernetesClusterClient()
        LOGGER.info("using KubernetesClusterClient")
    except Exception as exc:
        LOGGER.warning("Kubernetes API unavailable (%s); NullClusterClient", exc)
    return runtime.client


def workload_from_pod(pod: Mapping[str, Any]) -> str:
    """Deployment/StatefulSet/DaemonSet name, walking ReplicaSet ownerReferences."""
    metadata = _metadata(pod)
    for owner in _owners(metadata):
        kind = owner.get("kind")
        name = owner.get("name")
        if not isinstance(name, str) or not name:
            continue
        if kind in WORKLOAD_KINDS:
            return name
        if kind == "ReplicaSet":
            return _strip_hash(name)
    return str(metadata.get("name") or "unknown")


def _load_kubernetes_apis() -> tuple[Any, Any]:
    from kubernetes import client, config  # type: ignore[import-untyped]

    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()
    return client.CoreV1Api(), client.AppsV1Api()


def _decode_log_text(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return bytes(raw).decode("utf-8", errors="replace")
    return str(raw)


def _plain(obj: Any) -> Any:
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, datetime):
        return obj
    if isinstance(obj, dict):
        return {str(key): _plain(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(item) for item in obj]
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        return _plain(to_dict())
    if hasattr(obj, "__dict__"):
        return {
            str(key): _plain(value)
            for key, value in vars(obj).items()
            if not str(key).startswith("_")
        }
    return obj


def _mapping(value: object) -> dict[str, Any]:
    plain = _plain(value)
    return plain if isinstance(plain, dict) else {}


def _metadata(obj: Any) -> dict[str, Any]:
    return _mapping(_mapping(_plain(obj)).get("metadata"))


def _owners(meta: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = meta.get("ownerReferences") or meta.get("owner_references") or []
    if not isinstance(raw, list):
        return []
    return [_mapping(item) for item in raw]


def _list_items(listing: Any) -> list[dict[str, Any]]:
    plain = _plain(listing)
    if isinstance(plain, dict) and isinstance(plain.get("items"), list):
        return [_mapping(item) for item in plain["items"]]
    items = getattr(listing, "items", None)
    if isinstance(items, list):
        return [_mapping(item) for item in items]
    return []


def _pick(data: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _owned_by_workload(rs: Mapping[str, Any], workload: str) -> bool:
    return any(
        str(owner.get("kind") or "") in WORKLOAD_KINDS and owner.get("name") == workload
        for owner in _owners(_metadata(rs))
    )


def _containers(deploy: Mapping[str, Any]) -> list[dict[str, Any]]:
    spec = _mapping(deploy.get("spec"))
    template = _mapping(spec.get("template"))
    pod_spec = _mapping(template.get("spec"))
    containers = pod_spec.get("containers") or []
    if not isinstance(containers, list):
        return []
    return [_mapping(item) for item in containers]


def _strip_hash(name: str) -> str:
    return name.rsplit("-", 1)[0] if "-" in name else name


def _format_time(stamp: datetime) -> str:
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return stamp.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(raw: str) -> datetime | None:
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed
