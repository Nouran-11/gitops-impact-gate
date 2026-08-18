from __future__ import annotations

from impactgate.analysis.rules import (
    broken_selector,
    dangling_reference,
    drop_preexisting,
    mismatching_selector,
    orphaned_ingress,
    run_integrity_checks,
    unreachable_workload,
)
from impactgate.models import Finding, ResourceRef, Severity, compute_finding_id

from tests.helpers import graph_from_yaml, resources_from_yaml, selector_break_graphs

MATCHING = """
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

BROKEN = """
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


def test_broken_selector_ignores_deployment_match_labels() -> None:
    findings = broken_selector(
        graph_from_yaml(
            """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout-v2}}
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
    )
    assert findings == []


def test_broken_selector_positive() -> None:
    findings = broken_selector(graph_from_yaml(BROKEN))
    assert len(findings) == 1
    assert findings[0].rule == "broken-selector"
    assert findings[0].resource.key() == "demo/Service/checkout"
    assert findings[0].origin == "graph"


def test_broken_selector_negative() -> None:
    assert broken_selector(graph_from_yaml(MATCHING)) == []


def test_mismatching_selector_positive() -> None:
    findings = mismatching_selector(
        graph_from_yaml(
            """
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
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
    )
    assert len(findings) == 1
    assert findings[0].rule == "mismatching-selector"
    assert findings[0].resource.key() == "demo/Deployment/checkout"
    assert "checkout-v2" in findings[0].evidence


def test_mismatching_selector_negative() -> None:
    assert mismatching_selector(graph_from_yaml(MATCHING)) == []


def test_drop_preexisting_by_rule_and_resource() -> None:
    ref = ResourceRef(api_version="v1", kind="File", name="deployment.yaml")
    shared = Finding(
        id=compute_finding_id("KSV-0014", ref.key(), "ro"),
        origin="scanner",
        rule="KSV-0014",
        resource=ref,
        path=[ref.key()],
        evidence="deployment.yaml: Root file system is not read-only",
        severity_floor=Severity.HIGH,
    )
    extra = shared.model_copy(
        update={
            "id": compute_finding_id("broken-selector", "demo/Service/checkout", "x"),
            "origin": "graph",
            "rule": "broken-selector",
            "resource": ResourceRef(
                api_version="v1", kind="Service", name="checkout", namespace="demo"
            ),
        }
    )
    kept = drop_preexisting([shared, extra], [shared])
    assert [item.rule for item in kept] == ["broken-selector"]


def test_dangling_reference_positive() -> None:
    findings = dangling_reference(
        graph_from_yaml(
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
        - name: cfg
          configMap: {name: missing-config}
      containers: [{name: app, image: nginx:1.25}]
"""
        )
    )
    assert len(findings) == 1
    assert findings[0].rule == "dangling-reference"
    assert findings[0].resource.key() == "demo/Deployment/checkout"
    assert "missing-config" in findings[0].evidence


def test_dangling_reference_negative() -> None:
    findings = dangling_reference(
        graph_from_yaml(
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
    )
    assert findings == []


def test_orphaned_ingress_positive() -> None:
    findings = orphaned_ingress(
        graph_from_yaml(
            """
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
              service: {name: gone, port: {number: 80}}
"""
        )
    )
    assert len(findings) == 1
    assert findings[0].rule == "orphaned-ingress"
    assert findings[0].resource.key() == "demo/Ingress/public"


def test_orphaned_ingress_negative() -> None:
    findings = orphaned_ingress(
        graph_from_yaml(
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
    )
    assert findings == []


def test_unreachable_workload_positive() -> None:
    before = graph_from_yaml(MATCHING)
    after = graph_from_yaml(BROKEN)
    findings = unreachable_workload(after, before)
    assert len(findings) == 1
    assert findings[0].rule == "unreachable-workload"
    assert findings[0].resource.key() == "demo/Deployment/checkout"


def test_unreachable_workload_negative_still_selected() -> None:
    graph = graph_from_yaml(MATCHING)
    assert unreachable_workload(graph, graph) == []


def test_pre_existing_findings_are_not_new() -> None:
    after = graph_from_yaml(BROKEN)
    before = graph_from_yaml(BROKEN)
    findings = run_integrity_checks(after, before=before)
    assert findings == []


def test_resources_from_yaml_round_trip() -> None:
    resources = resources_from_yaml(MATCHING)
    assert {item.ref.kind for item in resources} == {"Deployment", "Service"}


def test_selector_break_graphs_change_labels() -> None:
    before, after, changed_files = selector_break_graphs()
    assert changed_files == ["deployment.yaml"]
    assert "demo/Service/checkout" in before
    assert "demo/Service/checkout" in after
    assert before.has_edge("demo/Service/checkout", "demo/Deployment/checkout")
    assert not after.has_edge("demo/Service/checkout", "demo/Deployment/checkout")
