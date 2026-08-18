from __future__ import annotations

from pathlib import Path

from impactgate.graph.builder import build_graph
from impactgate.graph.edges import (
    extract_claims,
    extract_env_from,
    extract_grants,
    extract_image,
    extract_mounts_config,
    extract_mounts_secret,
    extract_routes_to,
    extract_runs_as,
    extract_scales,
    extract_selects,
    extract_targets,
    image_key,
)
from impactgate.graph.parser import parse_directory, parse_text
from impactgate.models import EdgeKind, Resource, ResourceRef


def _resources(yaml_text: str) -> list[Resource]:
    result = parse_text(yaml_text, source_file="fixture.yaml")
    assert result.ok, result.errors
    return result.resources


def test_extract_selects_service_to_matching_deployment() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      containers: [{name: app, image: nginx:1.25}]
---
apiVersion: v1
kind: Service
metadata: {name: checkout, namespace: demo}
spec:
  selector: {app: checkout}
"""
    )
    edges = extract_selects(resources)
    workload_edges = [edge for edge in edges if edge.target.endswith("/Deployment/checkout")]
    assert len(workload_edges) == 1
    assert workload_edges[0].source == "demo/Service/checkout"
    assert workload_edges[0].kind == EdgeKind.SELECTS
    assert "app=checkout" in workload_edges[0].detail
    assert any("/LabelSet/" in edge.target for edge in edges)


def test_extract_selects_keeps_dangling_selector() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout-v2}}
  template:
    metadata: {labels: {app: checkout-v2}}
    spec:
      containers: [{name: app, image: nginx:1.25}]
---
apiVersion: v1
kind: Service
metadata: {name: checkout, namespace: demo}
spec:
  selector: {app: checkout}
"""
    )
    edges = extract_selects(resources)
    assert all(not edge.target.endswith("/Deployment/checkout") for edge in edges)
    dangling = [edge for edge in edges if "/LabelSet/" in edge.target]
    assert dangling
    assert dangling[0].kind == EdgeKind.SELECTS


def test_extract_routes_to_ingress_backend() -> None:
    resources = _resources(
        """
apiVersion: v1
kind: Service
metadata: {name: checkout, namespace: demo}
spec: {selector: {app: checkout}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: public, namespace: demo}
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: checkout, port: {number: 80}}
"""
    )
    edges = extract_routes_to(resources)
    assert len(edges) == 1
    assert edges[0].source == "demo/Ingress/public"
    assert edges[0].target == "demo/Service/checkout"
    assert edges[0].kind == EdgeKind.ROUTES_TO


def test_extract_routes_to_missing_service() -> None:
    resources = _resources(
        """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: public, namespace: demo}
spec:
  defaultBackend:
    service: {name: missing, port: {number: 80}}
"""
    )
    edges = extract_routes_to(resources)
    assert edges[0].target == "demo/Service/missing"


def test_extract_mounts_config() -> None:
    resources = _resources(
        """
apiVersion: v1
kind: ConfigMap
metadata: {name: app-config, namespace: demo}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      volumes:
        - name: cfg
          configMap: {name: app-config}
      containers: [{name: app, image: nginx:1.25}]
"""
    )
    edges = extract_mounts_config(resources)
    assert edges[0].kind == EdgeKind.MOUNTS_CONFIG
    assert edges[0].target == "demo/ConfigMap/app-config"


def test_extract_mounts_secret() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      volumes:
        - name: tls
          secret: {secretName: gone}
      containers: [{name: app, image: nginx:1.25}]
"""
    )
    edges = extract_mounts_secret(resources)
    assert edges[0].kind == EdgeKind.MOUNTS_SECRET
    assert edges[0].target == "demo/Secret/gone"


def test_extract_env_from_configmap_and_secret() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: db, namespace: demo}
spec:
  selector: {matchLabels: {app: db}}
  template:
    metadata: {labels: {app: db}}
    spec:
      containers:
        - name: db
          image: postgres:16
          envFrom:
            - configMapRef: {name: db-config}
          env:
            - name: PASS
              valueFrom:
                secretKeyRef: {name: db-pass, key: password}
"""
    )
    edges = extract_env_from(resources)
    targets = {edge.target for edge in edges}
    assert "demo/ConfigMap/db-config" in targets
    assert "demo/Secret/db-pass" in targets
    assert all(edge.kind == EdgeKind.ENV_FROM for edge in edges)


def test_extract_claims() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: checkout-data}
      containers: [{name: app, image: nginx:1.25}]
"""
    )
    edges = extract_claims(resources)
    assert edges[0].kind == EdgeKind.CLAIMS
    assert edges[0].target == "demo/PersistentVolumeClaim/checkout-data"


def test_extract_runs_as() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: agent, namespace: demo}
spec:
  selector: {matchLabels: {app: agent}}
  template:
    metadata: {labels: {app: agent}}
    spec:
      serviceAccountName: agent-sa
      containers: [{name: agent, image: nginx:1.25}]
"""
    )
    edges = extract_runs_as(resources)
    assert edges[0].kind == EdgeKind.RUNS_AS
    assert edges[0].target == "demo/ServiceAccount/agent-sa"


def test_extract_grants_rolebinding() -> None:
    resources = _resources(
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: reader, namespace: demo}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: app-sa, namespace: demo}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: bind, namespace: demo}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: reader}
subjects:
  - {kind: ServiceAccount, name: app-sa}
"""
    )
    edges = extract_grants(resources)
    targets = {edge.target for edge in edges}
    assert "demo/Role/reader" in targets
    assert "demo/ServiceAccount/app-sa" in targets
    assert all(edge.kind == EdgeKind.GRANTS for edge in edges)


def test_extract_grants_clusterrolebinding_unresolvable_sa() -> None:
    resources = _resources(
        """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: bind}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: admin}
subjects:
  - {kind: ServiceAccount, name: app-sa}
"""
    )
    edges = extract_grants(resources)
    targets = {edge.target for edge in edges}
    assert "_cluster/ClusterRole/admin" in targets
    assert "_cluster/MISSING/ServiceAccount/app-sa" in targets


def test_extract_scales() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      containers: [{name: app, image: nginx:1.25}]
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: checkout, namespace: demo}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: checkout}
"""
    )
    edges = extract_scales(resources)
    assert edges[0].kind == EdgeKind.SCALES
    assert edges[0].target == "demo/Deployment/checkout"


def test_extract_targets_network_policy() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      containers: [{name: app, image: nginx:1.25}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: checkout, namespace: demo}
spec:
  podSelector: {matchLabels: {app: checkout}}
"""
    )
    edges = extract_targets(resources)
    assert edges[0].kind == EdgeKind.TARGETS
    assert edges[0].target == "demo/Deployment/checkout"


def test_extract_image_virtual_node() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      initContainers: [{name: init, image: busybox:1.36}]
      containers: [{name: app, image: nginx:1.25}]
"""
    )
    edges = extract_image(resources)
    targets = {edge.target for edge in edges}
    assert image_key("nginx:1.25") in targets
    assert image_key("busybox:1.36") in targets
    assert all(edge.kind == EdgeKind.IMAGE for edge in edges)


def test_builder_marks_missing_secret() -> None:
    resources = _resources(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      volumes:
        - name: tls
          secret: {secretName: gone}
      containers: [{name: app, image: nginx:1.25}]
"""
    )
    graph = build_graph(resources)
    assert graph.nodes["demo/Secret/gone"]["missing"] is True
    assert graph.has_edge("demo/Deployment/checkout", "demo/Secret/gone")


def test_selector_break_demo_graph() -> None:
    root = Path(__file__).resolve().parents[1]
    parsed = parse_directory(root / "demo" / "manifests" / "selector-break")
    assert parsed.ok, parsed.errors
    graph = build_graph(parsed.resources)
    assert "demo/Deployment/checkout" in graph
    assert "demo/Service/checkout" in graph
    assert "demo/Ingress/public" in graph
    assert graph.has_edge("demo/Service/checkout", "demo/Deployment/checkout")
    service_to_deploy = graph.edges["demo/Service/checkout", "demo/Deployment/checkout"]
    assert service_to_deploy["kind"] == EdgeKind.SELECTS
    assert graph.has_edge("demo/Ingress/public", "demo/Service/checkout")
    assert graph.edges["demo/Ingress/public", "demo/Service/checkout"]["kind"] == EdgeKind.ROUTES_TO
    image_nodes = [node for node in graph.nodes if node.startswith("_cluster/Image/")]
    assert image_nodes


def test_resource_ref_used_in_graph_nodes() -> None:
    ref = ResourceRef(api_version="v1", kind="Service", name="checkout", namespace="demo")
    assert ref.key() in {
        resource.ref.key()
        for resource in _resources(
            """
apiVersion: v1
kind: Service
metadata: {name: checkout, namespace: demo}
spec: {selector: {app: checkout}}
"""
        )
    }
