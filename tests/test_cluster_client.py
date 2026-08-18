"""KubernetesClusterClient against a fake API (cluster-shaped, no kind cluster)."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from typing import Any

from impactgate.controller.actions import Action, AuditRecord, last_healthy_revision
from impactgate.controller.cluster import (
    AUDIT_ANNOTATION,
    READY_ANNOTATION,
    RESTART_ANNOTATION,
    KubernetesClusterClient,
    NullClusterClient,
    workload_from_pod,
)
from impactgate.controller.watcher import NullClusterClient as WatcherNull

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class FakeApiException(Exception):
    def __init__(self, status: int, reason: str = "not found") -> None:
        super().__init__(reason)
        self.status = status


def _deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class FakeCore:
    def __init__(self) -> None:
        self.logs: dict[tuple[str, str], str] = {}
        self.events: list[dict[str, Any]] = []

    def read_namespaced_pod_log(
        self,
        name: str,
        namespace: str,
        previous: bool = False,
        tail_lines: int | None = None,
    ) -> str:
        del previous, tail_lines
        return self.logs.get((namespace, name), "")

    def list_namespaced_event(self, namespace: str, field_selector: str = "") -> dict[str, Any]:
        del namespace
        name = ""
        for part in field_selector.split(","):
            if part.startswith("involvedObject.name="):
                name = part.split("=", 1)[1]
        items = [
            item
            for item in self.events
            if not name or (item.get("involvedObject") or {}).get("name") == name
        ]
        return {"items": items}

    def create_namespaced_event(self, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        event = copy.deepcopy(body)
        event.setdefault("metadata", {})["namespace"] = namespace
        self.events.append(event)
        return event


class FakeApps:
    def __init__(self) -> None:
        self.deployments: dict[tuple[str, str], dict[str, Any]] = {}
        self.replicasets: dict[tuple[str, str], dict[str, Any]] = {}

    def read_namespaced_deployment(self, name: str, namespace: str) -> dict[str, Any]:
        try:
            return self.deployments[(namespace, name)]
        except KeyError as exc:
            raise FakeApiException(404) from exc

    def patch_namespaced_deployment(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        key = (namespace, name)
        self.deployments[key] = _deep_merge(self.deployments[key], body)
        return self.deployments[key]

    def list_namespaced_replica_set(self, namespace: str, **_: object) -> dict[str, Any]:
        items = [item for (ns, _name), item in self.replicasets.items() if ns == namespace]
        return {"items": items}

    def read_namespaced_replica_set(self, name: str, namespace: str) -> dict[str, Any]:
        try:
            return self.replicasets[(namespace, name)]
        except KeyError as exc:
            raise FakeApiException(404) from exc

    def patch_namespaced_replica_set(
        self, name: str, namespace: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        key = (namespace, name)
        self.replicasets[key] = _deep_merge(self.replicasets[key], body)
        return self.replicasets[key]


def _deployment() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "storefront", "namespace": "demo", "annotations": {}},
        "spec": {
            "replicas": 1,
            "template": {
                "metadata": {"labels": {"app": "storefront"}},
                "spec": {
                    "containers": [
                        {
                            "name": "storefront",
                            "image": "nginx:doesnotexist",
                            "resources": {"limits": {"memory": "256Mi"}},
                        }
                    ]
                },
            },
        },
    }


def _replica_set(
    name: str,
    image: str,
    *,
    ready: int = 1,
    desired: int = 1,
    annotations: dict[str, str] | None = None,
) -> dict[str, Any]:
    hash_part = name.rsplit("-", 1)[-1]
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": name,
            "namespace": "demo",
            "annotations": dict(annotations or {}),
            "ownerReferences": [
                {"apiVersion": "apps/v1", "kind": "Deployment", "name": "storefront"}
            ],
        },
        "spec": {
            "replicas": desired,
            "template": {
                "metadata": {
                    "labels": {"app": "storefront", "pod-template-hash": hash_part},
                },
                "spec": {"containers": [{"name": "storefront", "image": image}]},
            },
        },
        "status": {"replicas": desired, "readyReplicas": ready},
    }


def _client(apps: FakeApps, core: FakeCore | None = None) -> KubernetesClusterClient:
    return KubernetesClusterClient(core=core or FakeCore(), apps=apps, clock=lambda: NOW)


def test_watcher_reexports_null_client() -> None:
    assert WatcherNull is NullClusterClient


def test_null_client_does_not_mutate() -> None:
    client = NullClusterClient()
    assert client.rollback("demo", "storefront", "rs-1") == "rolled-back:rs-1"
    assert client.restart("demo", "storefront") == "restarted"
    assert client.bump_memory("demo", "storefront", "384Mi") == "memory-bumped:384Mi"
    assert client.scale_out("demo", "storefront") == "scaled-out"
    assert client.list_revisions("demo", "storefront") == []
    client.emit_event("demo", "storefront", "noop")
    client.record_audit(
        AuditRecord(
            workload="demo/storefront",
            evidence="x",
            classification=Action.ROLLBACK,
            action=Action.ROLLBACK,
            outcome="dry-run",
            dry_run=True,
        )
    )


def test_list_revisions_stamps_ready_since_on_first_observation() -> None:
    apps = FakeApps()
    apps.deployments[("demo", "storefront")] = _deployment()
    apps.replicasets[("demo", "storefront-abc")] = _replica_set(
        "storefront-abc", "nginx:1.25", ready=1
    )
    client = _client(apps)
    revisions = client.list_revisions("demo", "storefront")
    assert len(revisions) == 1
    assert revisions[0].ready_since == NOW
    assert last_healthy_revision(revisions, now=NOW) is None
    stamped = apps.replicasets[("demo", "storefront-abc")]["metadata"]["annotations"]
    assert stamped[READY_ANNOTATION] == "2026-01-01T12:00:00Z"


def test_list_revisions_healthy_after_ten_minutes() -> None:
    apps = FakeApps()
    apps.replicasets[("demo", "storefront-healthy")] = _replica_set(
        "storefront-healthy",
        "nginx:1.25",
        annotations={READY_ANNOTATION: "2026-01-01T11:45:00Z"},
    )
    apps.replicasets[("demo", "storefront-bad")] = _replica_set(
        "storefront-bad", "nginx:doesnotexist", ready=0, desired=1
    )
    client = _client(apps)
    revisions = client.list_revisions("demo", "storefront")
    healthy = last_healthy_revision(revisions, now=NOW)
    assert healthy is not None
    assert healthy.name == "storefront-healthy"


def test_rollback_copies_healthy_pod_template() -> None:
    apps = FakeApps()
    apps.deployments[("demo", "storefront")] = _deployment()
    apps.replicasets[("demo", "storefront-healthy")] = _replica_set(
        "storefront-healthy", "nginx:1.25"
    )
    client = _client(apps)
    outcome = client.rollback("demo", "storefront", "storefront-healthy")
    assert outcome == "rolled-back:storefront-healthy"
    template = apps.deployments[("demo", "storefront")]["spec"]["template"]
    assert template["spec"]["containers"][0]["image"] == "nginx:1.25"
    assert "pod-template-hash" not in template["metadata"]["labels"]


def test_restart_sets_restarted_at_annotation() -> None:
    apps = FakeApps()
    apps.deployments[("demo", "storefront")] = _deployment()
    client = _client(apps)
    assert client.restart("demo", "storefront") == "restarted"
    annotations = apps.deployments[("demo", "storefront")]["spec"]["template"]["metadata"][
        "annotations"
    ]
    assert annotations[RESTART_ANNOTATION] == "2026-01-01T12:00:00Z"


def test_bump_memory_patches_container_limit() -> None:
    apps = FakeApps()
    apps.deployments[("demo", "storefront")] = _deployment()
    client = _client(apps)
    assert client.current_memory_limit("demo", "storefront") == "256Mi"
    assert client.bump_memory("demo", "storefront", "384Mi") == "memory-bumped:384Mi"
    container = apps.deployments[("demo", "storefront")]["spec"]["template"]["spec"][
        "containers"
    ][0]
    assert container["resources"]["limits"]["memory"] == "384Mi"


def test_scale_out_increments_replicas() -> None:
    apps = FakeApps()
    apps.deployments[("demo", "storefront")] = _deployment()
    client = _client(apps)
    assert client.scale_out("demo", "storefront") == "scaled-out:2"
    assert apps.deployments[("demo", "storefront")]["spec"]["replicas"] == 2


def test_emit_event_and_record_audit_hit_the_api() -> None:
    apps = FakeApps()
    core = FakeCore()
    apps.deployments[("demo", "storefront")] = _deployment()
    client = _client(apps, core)
    client.emit_event("demo", "storefront", "impactgate rollback: rolled-back:rs")
    assert core.events
    assert core.events[0]["reason"] == "ImpactGateRemediation"
    assert core.events[0]["involvedObject"]["name"] == "storefront"
    record = AuditRecord(
        workload="demo/storefront",
        evidence="ErrImagePull",
        classification=Action.ROLLBACK,
        action=Action.ROLLBACK,
        outcome="rolled-back:storefront-healthy",
        dry_run=False,
        at=NOW,
    )
    client.record_audit(record)
    raw = apps.deployments[("demo", "storefront")]["metadata"]["annotations"][AUDIT_ANNOTATION]
    payload = json.loads(raw)
    assert payload["action"] == "rollback"
    assert payload["outcome"] == "rolled-back:storefront-healthy"


def test_previous_logs_and_pod_events() -> None:
    core = FakeCore()
    core.logs[("demo", "pod-0")] = "previous boom"
    core.events.append(
        {
            "reason": "BackOff",
            "message": "pull failed",
            "involvedObject": {"name": "pod-0"},
        }
    )
    client = KubernetesClusterClient(core=core, apps=FakeApps(), clock=lambda: NOW)
    assert client.previous_logs("demo", "pod-0") == "previous boom"
    assert client.pod_events("demo", "pod-0") == ["BackOff: pull failed"]


def test_owning_workload_follows_replicaset_owner() -> None:
    apps = FakeApps()
    apps.replicasets[("demo", "storefront-abc")] = _replica_set("storefront-abc", "nginx:1.25")
    client = _client(apps)
    pod = {
        "metadata": {
            "name": "storefront-abc-xyz",
            "namespace": "demo",
            "ownerReferences": [{"kind": "ReplicaSet", "name": "storefront-abc"}],
        }
    }
    assert client.owning_workload("demo", pod) == "storefront"


def _kind_storefront_pod() -> dict[str, Any]:
    """ReplicaSet-owned pod body as returned by the kind API / kopf watch.

    Matches demo/storefront after `kubectl set image ... nginx:doesnotexist`:
    Pod storefront-5f9b476644-xr5x5 owned by ReplicaSet storefront-5f9b476644
    owned by Deployment storefront.
    """
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "storefront-5f9b476644-xr5x5",
            "namespace": "demo",
            "uid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "labels": {
                "app": "storefront",
                "impactgate.io/managed": "true",
                "pod-template-hash": "5f9b476644",
            },
            "ownerReferences": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "ReplicaSet",
                    "name": "storefront-5f9b476644",
                    "uid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    "controller": True,
                    "blockOwnerDeletion": True,
                }
            ],
        },
        "spec": {
            "containers": [{"name": "storefront", "image": "nginx:doesnotexist"}],
        },
        "status": {
            "phase": "Pending",
            "containerStatuses": [
                {
                    "name": "storefront",
                    "ready": False,
                    "restartCount": 0,
                    "state": {
                        "waiting": {
                            "reason": "ErrImagePull",
                            "message": 'Failed to pull image "nginx:doesnotexist"',
                        }
                    },
                }
            ],
        },
    }


def test_kind_replicaset_pod_body_resolves_to_deployment() -> None:
    """kopf delivers a Body/MappingView, not a dict. Dict-only tests missed this."""
    import kopf

    raw = _kind_storefront_pod()
    body = kopf.Body(raw)
    assert type(body).__name__ == "Body"
    assert not isinstance(body, dict)
    assert list(vars(body)) == [] or all(str(key).startswith("_") for key in vars(body))

    assert workload_from_pod(raw) == "storefront"
    assert workload_from_pod(body) == "storefront"
    assert workload_from_pod(body.metadata) == "storefront"

    apps = FakeApps()
    apps.replicasets[("demo", "storefront-5f9b476644")] = _replica_set(
        "storefront-5f9b476644", "nginx:doesnotexist", ready=0
    )
    client = _client(apps)
    assert client.owning_workload("demo", body) == "storefront"
    assert client.owning_workload("demo", raw) == "storefront"

    from impactgate.controller.watcher import diagnose

    diagnosis = diagnose(body, client=client, reason="ErrImagePull")
    assert diagnosis.namespace == "demo"
    assert diagnosis.pod == "storefront-5f9b476644-xr5x5"
    assert diagnosis.workload == "storefront"


def test_healthy_marker_cleared_when_replicas_not_ready() -> None:
    apps = FakeApps()
    apps.replicasets[("demo", "storefront-abc")] = _replica_set(
        "storefront-abc",
        "nginx:1.25",
        ready=0,
        annotations={READY_ANNOTATION: "2026-01-01T11:00:00Z"},
    )
    client = _client(apps)
    revisions = client.list_revisions("demo", "storefront")
    assert revisions[0].ready_since is None
    assert (
        apps.replicasets[("demo", "storefront-abc")]["metadata"]["annotations"][READY_ANNOTATION]
        == ""
    )
