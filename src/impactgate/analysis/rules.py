"""Graph-level integrity checks."""

from __future__ import annotations

from collections.abc import Callable

import networkx as nx

from impactgate.graph.edges import (
    SELECTS_WORKLOAD_KINDS,
    is_virtual_key,
    pod_labels,
    selector_matches,
    service_selector,
    service_selects_workload,
)
from impactgate.models import EdgeKind, Finding, Resource, Severity, compute_finding_id

DANGLING_KINDS = frozenset(
    {
        "ConfigMap",
        "Secret",
        "PersistentVolumeClaim",
        "ServiceAccount",
        "Role",
        "ClusterRole",
    }
)

Check = Callable[..., list[Finding]]


def run_integrity_checks(
    after: nx.DiGraph[str],
    *,
    before: nx.DiGraph[str] | None = None,
) -> list[Finding]:
    """Run checks 1–4 against ``after`` and drop findings already present in ``before``."""
    after_findings: list[Finding] = []
    for check in CHECKS:
        after_findings.extend(check(after, before))
    if before is None:
        return after_findings
    before_findings: list[Finding] = []
    for check in CHECKS:
        before_findings.extend(check(before, before))
    preexisting = {(item.rule, item.resource.key()) for item in before_findings}
    return [item for item in after_findings if (item.rule, item.resource.key()) not in preexisting]


def broken_selector(
    graph: nx.DiGraph[str],
    before: nx.DiGraph[str] | None = None,
) -> list[Finding]:
    del before
    findings: list[Finding] = []
    for _, data in graph.nodes(data=True):
        if data.get("kind") != "Service":
            continue
        resource = data.get("resource")
        if not isinstance(resource, Resource):
            continue
        selector = service_selector(resource)
        if not selector:
            continue
        if _matches_workload(graph, resource):
            continue
        evidence = f"spec.selector {_format_selector(selector)} matches no workload"
        findings.append(_finding("broken-selector", resource, evidence))
    return findings


def dangling_reference(
    graph: nx.DiGraph[str],
    before: nx.DiGraph[str] | None = None,
) -> list[Finding]:
    del before
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for source, target, edge_data in graph.edges(data=True):
        target_data = graph.nodes[target]
        kind = _kind_from_key(target)
        if kind not in DANGLING_KINDS or is_virtual_key(target):
            continue
        if target_data.get("type") == "resource" and not target_data.get("missing"):
            continue
        source_data = graph.nodes[source]
        resource = source_data.get("resource")
        if not isinstance(resource, Resource):
            continue
        key = (resource.ref.key(), target)
        if key in seen:
            continue
        seen.add(key)
        detail = str(edge_data.get("detail", target))
        evidence = f"{detail} -> {target} (missing {kind})"
        findings.append(_finding("dangling-reference", resource, evidence))
    return findings


def orphaned_ingress(
    graph: nx.DiGraph[str],
    before: nx.DiGraph[str] | None = None,
) -> list[Finding]:
    del before
    findings: list[Finding] = []
    for source, target, edge_data in graph.edges(data=True):
        if edge_data.get("kind") != EdgeKind.ROUTES_TO:
            continue
        source_data = graph.nodes[source]
        if source_data.get("kind") != "Ingress":
            continue
        target_data = graph.nodes[target]
        if target_data.get("type") == "resource" and not target_data.get("missing"):
            continue
        resource = source_data.get("resource")
        if not isinstance(resource, Resource):
            continue
        detail = str(edge_data.get("detail", target))
        evidence = f"{detail} -> {target} (service missing)"
        findings.append(_finding("orphaned-ingress", resource, evidence))
    return findings


def unreachable_workload(
    graph: nx.DiGraph[str],
    before: nx.DiGraph[str] | None = None,
) -> list[Finding]:
    if before is None:
        return []
    findings: list[Finding] = []
    for node, data in graph.nodes(data=True):
        if data.get("kind") not in SELECTS_WORKLOAD_KINDS:
            continue
        resource = data.get("resource")
        if not isinstance(resource, Resource):
            continue
        if not _is_selected(before, node):
            continue
        if _is_selected(graph, node):
            continue
        evidence = f"{node} was selected by a Service before this change and is not selected after"
        findings.append(_finding("unreachable-workload", resource, evidence))
    return findings


CHECKS: tuple[Check, ...] = (
    broken_selector,
    dangling_reference,
    orphaned_ingress,
    unreachable_workload,
)


def _finding(rule: str, resource: Resource, evidence: str) -> Finding:
    return Finding(
        id=compute_finding_id(rule, resource.ref.key(), evidence),
        origin="graph",
        rule=rule,
        resource=resource.ref,
        path=[resource.ref.key()],
        evidence=evidence,
        severity_floor=Severity.LOW,
    )


def _matches_workload(graph: nx.DiGraph[str], service: Resource) -> bool:
    """Match Service.spec.selector against pod template labels, not Deployment matchLabels."""
    for _, data in graph.nodes(data=True):
        if data.get("kind") not in SELECTS_WORKLOAD_KINDS or data.get("missing"):
            continue
        workload = data.get("resource")
        if isinstance(workload, Resource) and service_selects_workload(service, workload):
            return True
    return False


def _is_selected(graph: nx.DiGraph[str], workload: str) -> bool:
    if workload not in graph:
        return False
    resource = graph.nodes[workload].get("resource")
    if not isinstance(resource, Resource):
        return False
    labels = pod_labels(resource)
    if labels is None:
        return False
    for _, data in graph.nodes(data=True):
        if data.get("kind") != "Service":
            continue
        service = data.get("resource")
        if not isinstance(service, Resource):
            continue
        selector = service_selector(service)
        if selector and selector_matches(selector, labels) and _same_namespace(service, resource):
            return True
    return False


def _same_namespace(left: Resource, right: Resource) -> bool:
    return left.ref.namespace == right.ref.namespace


def _format_selector(selector: dict[str, str]) -> str:
    if not selector:
        return "<empty>"
    return ",".join(f"{key}={value}" for key, value in sorted(selector.items()))


def _kind_from_key(key: str) -> str:
    parts = key.split("/")
    if len(parts) >= 2:
        return parts[1]
    return ""
