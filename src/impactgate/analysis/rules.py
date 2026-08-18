"""Graph-level integrity checks."""

from __future__ import annotations

from collections.abc import Callable

import networkx as nx

from impactgate.graph.edges import SELECTS_WORKLOAD_KINDS, is_virtual_key
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
    for node, data in graph.nodes(data=True):
        if data.get("kind") != "Service":
            continue
        resource = data.get("resource")
        if not isinstance(resource, Resource):
            continue
        selector = _service_selector(resource)
        if selector is None:
            continue
        if _selects_workload(graph, node):
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


def _selects_workload(graph: nx.DiGraph[str], service: str) -> bool:
    for _, target, edge_data in graph.out_edges(service, data=True):
        if edge_data.get("kind") != EdgeKind.SELECTS:
            continue
        target_data = graph.nodes[target]
        if target_data.get("kind") in SELECTS_WORKLOAD_KINDS and not target_data.get("missing"):
            return True
    return False


def _is_selected(graph: nx.DiGraph[str], workload: str) -> bool:
    if workload not in graph:
        return False
    for source, _, edge_data in graph.in_edges(workload, data=True):
        if edge_data.get("kind") != EdgeKind.SELECTS:
            continue
        if graph.nodes[source].get("kind") == "Service":
            return True
    return False


def _service_selector(resource: Resource) -> dict[str, str] | None:
    spec = resource.spec.get("spec")
    if not isinstance(spec, dict):
        return None
    selector = spec.get("selector")
    if selector is None:
        return None
    if not isinstance(selector, dict):
        return None
    return {str(key): str(value) for key, value in selector.items()}


def _format_selector(selector: dict[str, str]) -> str:
    if not selector:
        return "<empty>"
    return ",".join(f"{key}={value}" for key, value in sorted(selector.items()))


def _kind_from_key(key: str) -> str:
    parts = key.split("/")
    if len(parts) >= 2:
        return parts[1]
    return ""
