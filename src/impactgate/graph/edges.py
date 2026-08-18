"""One function per edge extraction rule."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from impactgate.models import Edge, EdgeKind, Resource, ResourceRef

SELECTS_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet"})
POD_TEMPLATE_WORKLOAD_KINDS = frozenset(
    {
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Job",
        "CronJob",
        "Pod",
    }
)
CLUSTER_SCOPED_KINDS = frozenset(
    {
        "ClusterRole",
        "ClusterRoleBinding",
        "Namespace",
        "PersistentVolume",
        "StorageClass",
        "Node",
        "CustomResourceDefinition",
    }
)


def extract_all(resources: Sequence[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for extractor in EXTRACTORS:
        edges.extend(extractor(list(resources)))
    return edges


def extract_selects(resources: list[Resource]) -> list[Edge]:
    workloads = [item for item in resources if item.ref.kind in SELECTS_WORKLOAD_KINDS]
    edges: list[Edge] = []
    for service in resources:
        if service.ref.kind != "Service":
            continue
        selector = _as_str_map(_nested(service.spec, "spec", "selector"))
        if selector is None:
            continue
        detail = f"selector {_format_labels(selector)}"
        labelset_target = _labelset_key(service.ref.namespace, selector)
        edges.append(
            Edge(
                source=service.ref.key(),
                target=labelset_target,
                kind=EdgeKind.SELECTS,
                detail=detail,
            )
        )
        for workload in workloads:
            if not _same_namespace(service, workload):
                continue
            labels = pod_labels(workload)
            if labels is not None and _selector_matches(selector, labels):
                edges.append(
                    Edge(
                        source=service.ref.key(),
                        target=workload.ref.key(),
                        kind=EdgeKind.SELECTS,
                        detail=detail,
                    )
                )
    return edges


def extract_routes_to(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for ingress in resources:
        if ingress.ref.kind != "Ingress":
            continue
        names: list[str] = []
        default_backend = _nested(ingress.spec, "spec", "defaultBackend", "service", "name")
        if isinstance(default_backend, str) and default_backend:
            names.append(default_backend)
        for rule in _as_list(_nested(ingress.spec, "spec", "rules")):
            paths = _nested(rule, "http", "paths")
            for path in _as_list(paths):
                name = _nested(path, "backend", "service", "name")
                if isinstance(name, str) and name:
                    names.append(name)
        for name in names:
            edges.append(
                Edge(
                    source=ingress.ref.key(),
                    target=_namespaced_key(ingress, kind="Service", name=name),
                    kind=EdgeKind.ROUTES_TO,
                    detail=f"backend service={name}",
                )
            )
    return edges


def extract_mounts_config(resources: list[Resource]) -> list[Edge]:
    return _mount_edges(resources, volume_key="configMap", name_key="name", kind="ConfigMap")


def extract_mounts_secret(resources: list[Resource]) -> list[Edge]:
    return _mount_edges(resources, volume_key="secret", name_key="secretName", kind="Secret")


def extract_env_from(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for workload in resources:
        spec = pod_spec(workload)
        if spec is None:
            continue
        for container in _containers(spec):
            for env_from in _as_list(container.get("envFrom")):
                if not isinstance(env_from, dict):
                    continue
                cm = _nested(env_from, "configMapRef", "name")
                if isinstance(cm, str) and cm:
                    edges.append(
                        _ref_edge(
                            workload,
                            kind="ConfigMap",
                            name=cm,
                            edge_kind=EdgeKind.ENV_FROM,
                            detail=f"envFrom configMapRef={cm}",
                        )
                    )
                secret = _nested(env_from, "secretRef", "name")
                if isinstance(secret, str) and secret:
                    edges.append(
                        _ref_edge(
                            workload,
                            kind="Secret",
                            name=secret,
                            edge_kind=EdgeKind.ENV_FROM,
                            detail=f"envFrom secretRef={secret}",
                        )
                    )
            for env in _as_list(container.get("env")):
                if not isinstance(env, dict):
                    continue
                cm = _nested(env, "valueFrom", "configMapKeyRef", "name")
                if isinstance(cm, str) and cm:
                    edges.append(
                        _ref_edge(
                            workload,
                            kind="ConfigMap",
                            name=cm,
                            edge_kind=EdgeKind.ENV_FROM,
                            detail=f"env valueFrom configMapKeyRef={cm}",
                        )
                    )
                secret = _nested(env, "valueFrom", "secretKeyRef", "name")
                if isinstance(secret, str) and secret:
                    edges.append(
                        _ref_edge(
                            workload,
                            kind="Secret",
                            name=secret,
                            edge_kind=EdgeKind.ENV_FROM,
                            detail=f"env valueFrom secretKeyRef={secret}",
                        )
                    )
    return edges


def extract_claims(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for workload in resources:
        spec = pod_spec(workload)
        if spec is None:
            continue
        for volume in _as_list(spec.get("volumes")):
            if not isinstance(volume, dict):
                continue
            claim = _nested(volume, "persistentVolumeClaim", "claimName")
            if isinstance(claim, str) and claim:
                edges.append(
                    _ref_edge(
                        workload,
                        kind="PersistentVolumeClaim",
                        name=claim,
                        edge_kind=EdgeKind.CLAIMS,
                        detail=f"claimName {claim}",
                    )
                )
    return edges


def extract_runs_as(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for workload in resources:
        spec = pod_spec(workload)
        if spec is None:
            continue
        name = spec.get("serviceAccountName")
        if isinstance(name, str) and name:
            edges.append(
                _ref_edge(
                    workload,
                    kind="ServiceAccount",
                    name=name,
                    edge_kind=EdgeKind.RUNS_AS,
                    detail=f"serviceAccountName {name}",
                )
            )
    return edges


def extract_grants(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for binding in resources:
        if binding.ref.kind not in {"RoleBinding", "ClusterRoleBinding"}:
            continue
        role_ref = _as_dict(_nested(binding.spec, "roleRef"))
        role_kind = role_ref.get("kind")
        role_name = role_ref.get("name")
        role_api = role_ref.get("apiGroup", "rbac.authorization.k8s.io")
        if isinstance(role_kind, str) and isinstance(role_name, str):
            cluster_scoped = role_kind == "ClusterRole"
            role_api_version = (
                f"{role_api}/v1" if isinstance(role_api, str) else "rbac.authorization.k8s.io/v1"
            )
            target = _target_key(
                binding,
                kind=role_kind,
                name=role_name,
                api_version=role_api_version,
                cluster_scoped=cluster_scoped,
            )
            edges.append(
                Edge(
                    source=binding.ref.key(),
                    target=target,
                    kind=EdgeKind.GRANTS,
                    detail=f"roleRef {role_kind}/{role_name}",
                )
            )
        for subject in _as_list(_nested(binding.spec, "subjects")):
            if not isinstance(subject, dict):
                continue
            if subject.get("kind") != "ServiceAccount":
                continue
            sa_name = subject.get("name")
            if not isinstance(sa_name, str) or not sa_name:
                continue
            sa_ns = subject.get("namespace")
            namespace = sa_ns if isinstance(sa_ns, str) else None
            if namespace is None and binding.ref.kind == "ClusterRoleBinding":
                target = _unresolvable_sa_key(sa_name)
            else:
                target = _target_key(
                    binding,
                    kind="ServiceAccount",
                    name=sa_name,
                    namespace=namespace,
                    api_version="v1",
                    cluster_scoped=False,
                )
            edges.append(
                Edge(
                    source=binding.ref.key(),
                    target=target,
                    kind=EdgeKind.GRANTS,
                    detail=f"subject ServiceAccount/{sa_name}",
                )
            )
    return edges


def extract_scales(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for hpa in resources:
        if hpa.ref.kind != "HorizontalPodAutoscaler":
            continue
        ref = _as_dict(_nested(hpa.spec, "spec", "scaleTargetRef"))
        kind = ref.get("kind")
        name = ref.get("name")
        api_version = ref.get("apiVersion", "apps/v1")
        if not isinstance(kind, str) or not isinstance(name, str):
            continue
        if not isinstance(api_version, str):
            api_version = "apps/v1"
        edges.append(
            Edge(
                source=hpa.ref.key(),
                target=_target_key(
                    hpa,
                    kind=kind,
                    name=name,
                    api_version=api_version,
                    cluster_scoped=False,
                ),
                kind=EdgeKind.SCALES,
                detail=f"scaleTargetRef {kind}/{name}",
            )
        )
    return edges


def extract_targets(resources: list[Resource]) -> list[Edge]:
    workloads = [item for item in resources if item.ref.kind in SELECTS_WORKLOAD_KINDS]
    edges: list[Edge] = []
    for policy in resources:
        if policy.ref.kind != "NetworkPolicy":
            continue
        selector = _as_str_map(_nested(policy.spec, "spec", "podSelector", "matchLabels"))
        if selector is None:
            selector = {}
        detail = f"podSelector {_format_labels(selector)}"
        for workload in workloads:
            if not _same_namespace(policy, workload):
                continue
            labels = pod_labels(workload)
            if labels is not None and _selector_matches(selector, labels):
                edges.append(
                    Edge(
                        source=policy.ref.key(),
                        target=workload.ref.key(),
                        kind=EdgeKind.TARGETS,
                        detail=detail,
                    )
                )
    return edges


def extract_image(resources: list[Resource]) -> list[Edge]:
    edges: list[Edge] = []
    for workload in resources:
        spec = pod_spec(workload)
        if spec is None:
            continue
        for container in _containers(spec):
            image = container.get("image")
            if isinstance(image, str) and image:
                edges.append(
                    Edge(
                        source=workload.ref.key(),
                        target=image_key(image),
                        kind=EdgeKind.IMAGE,
                        detail=f"image {image}",
                    )
                )
    return edges


EXTRACTORS: tuple[Callable[[list[Resource]], list[Edge]], ...] = (
    extract_selects,
    extract_routes_to,
    extract_mounts_config,
    extract_mounts_secret,
    extract_env_from,
    extract_claims,
    extract_runs_as,
    extract_grants,
    extract_scales,
    extract_targets,
    extract_image,
)


def pod_spec(resource: Resource) -> dict[str, Any] | None:
    kind = resource.ref.kind
    if kind not in POD_TEMPLATE_WORKLOAD_KINDS:
        return None
    if kind == "Pod":
        spec = resource.spec.get("spec")
        return spec if isinstance(spec, dict) else None
    if kind == "CronJob":
        spec = _nested(resource.spec, "spec", "jobTemplate", "spec", "template", "spec")
        return spec if isinstance(spec, dict) else None
    spec = _nested(resource.spec, "spec", "template", "spec")
    return spec if isinstance(spec, dict) else None


def pod_labels(resource: Resource) -> dict[str, str] | None:
    kind = resource.ref.kind
    if kind == "Pod":
        labels = _nested(resource.spec, "metadata", "labels")
        return _as_str_map(labels) or {}
    if kind == "CronJob":
        labels = _nested(
            resource.spec, "spec", "jobTemplate", "spec", "template", "metadata", "labels"
        )
        return _as_str_map(labels)
    if kind in POD_TEMPLATE_WORKLOAD_KINDS:
        labels = _nested(resource.spec, "spec", "template", "metadata", "labels")
        return _as_str_map(labels)
    return None


def image_key(image: str) -> str:
    return f"_cluster/Image/{image}"


def is_virtual_key(key: str) -> bool:
    parts = key.split("/")
    return len(parts) >= 3 and parts[1] in {"Image", "LabelSet", "MISSING"}


def _mount_edges(
    resources: list[Resource],
    *,
    volume_key: str,
    name_key: str,
    kind: str,
) -> list[Edge]:
    edge_kind = EdgeKind.MOUNTS_CONFIG if kind == "ConfigMap" else EdgeKind.MOUNTS_SECRET
    edges: list[Edge] = []
    for workload in resources:
        spec = pod_spec(workload)
        if spec is None:
            continue
        for volume in _as_list(spec.get("volumes")):
            if not isinstance(volume, dict):
                continue
            source = volume.get(volume_key)
            if not isinstance(source, dict):
                continue
            name = source.get(name_key)
            if isinstance(name, str) and name:
                edges.append(
                    _ref_edge(
                        workload,
                        kind=kind,
                        name=name,
                        edge_kind=edge_kind,
                        detail=f"volume {volume_key}={name}",
                    )
                )
    return edges


def _ref_edge(
    source: Resource,
    *,
    kind: str,
    name: str,
    edge_kind: EdgeKind,
    detail: str,
    namespace: str | None = None,
    cluster_scoped: bool = False,
) -> Edge:
    return Edge(
        source=source.ref.key(),
        target=_target_key(
            source,
            kind=kind,
            name=name,
            namespace=namespace,
            cluster_scoped=cluster_scoped,
        ),
        kind=edge_kind,
        detail=detail,
    )


def _target_key(
    source: Resource,
    *,
    kind: str,
    name: str,
    api_version: str = "v1",
    namespace: str | None = None,
    cluster_scoped: bool = False,
) -> str:
    if cluster_scoped or kind in CLUSTER_SCOPED_KINDS:
        ns = None
    elif namespace is not None:
        ns = namespace
    else:
        ns = source.ref.namespace
    return ResourceRef(api_version=api_version, kind=kind, name=name, namespace=ns).key()


def _namespaced_key(source: Resource, *, kind: str, name: str) -> str:
    return _target_key(source, kind=kind, name=name)


def _unresolvable_sa_key(name: str) -> str:
    return f"_cluster/MISSING/ServiceAccount/{name}"


def _labelset_key(namespace: str | None, labels: Mapping[str, str]) -> str:
    ns = namespace or "_cluster"
    return f"{ns}/LabelSet/{_format_labels(labels)}"


def _format_labels(labels: Mapping[str, str]) -> str:
    if not labels:
        return "<empty>"
    return ",".join(f"{key}={value}" for key, value in sorted(labels.items()))


def _selector_matches(selector: Mapping[str, str], labels: Mapping[str, str]) -> bool:
    return all(labels.get(key) == value for key, value in selector.items())


def _same_namespace(left: Resource, right: Resource) -> bool:
    return left.ref.namespace == right.ref.namespace


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_str_map(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return None
    result: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, str):
            result[key] = item
    return result


def _nested(value: object, *keys: str) -> object:
    current: object = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _containers(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    for key in ("initContainers", "containers"):
        for item in _as_list(spec.get(key)):
            if isinstance(item, dict):
                containers.append(item)
    return containers
