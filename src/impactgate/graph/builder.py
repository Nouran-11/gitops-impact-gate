"""Resource objects -> networkx DiGraph."""

from __future__ import annotations

from collections.abc import Sequence

import networkx as nx

from impactgate.graph.edges import extract_all, is_virtual_key
from impactgate.models import Edge, Resource

NODE_TYPE_RESOURCE = "resource"
NODE_TYPE_VIRTUAL = "virtual"
NODE_TYPE_MISSING = "missing"


def build_graph(resources: Sequence[Resource]) -> nx.DiGraph[str]:
    """Build a directed graph of resources, virtual nodes, and dangling targets."""
    graph: nx.DiGraph[str] = nx.DiGraph()
    for resource in resources:
        _add_resource_node(graph, resource)
    for edge in extract_all(resources):
        _ensure_endpoint(graph, edge.source)
        _ensure_endpoint(graph, edge.target)
        _add_edge(graph, edge)
    return graph


def _add_resource_node(graph: nx.DiGraph[str], resource: Resource) -> None:
    graph.add_node(
        resource.ref.key(),
        type=NODE_TYPE_RESOURCE,
        kind=resource.ref.kind,
        missing=False,
        resource=resource,
        namespace=resource.ref.namespace,
    )


def _ensure_endpoint(graph: nx.DiGraph[str], key: str) -> None:
    if key in graph:
        return
    if is_virtual_key(key):
        kind = key.split("/")[1]
        graph.add_node(
            key,
            type=NODE_TYPE_VIRTUAL,
            kind=kind,
            missing=False,
            resource=None,
            namespace=_namespace_from_key(key),
        )
        return
    graph.add_node(
        key,
        type=NODE_TYPE_MISSING,
        kind="MISSING",
        missing=True,
        resource=None,
        namespace=_namespace_from_key(key),
    )


def _add_edge(graph: nx.DiGraph[str], edge: Edge) -> None:
    existing = graph.get_edge_data(edge.source, edge.target)
    if existing is None:
        graph.add_edge(
            edge.source,
            edge.target,
            kind=edge.kind,
            detail=edge.detail,
            kinds=[edge.kind],
        )
        return
    kinds = list(existing.get("kinds", [existing["kind"]]))
    if edge.kind not in kinds:
        kinds.append(edge.kind)
    existing["kinds"] = kinds
    existing["kind"] = kinds[0]
    if edge.detail not in str(existing.get("detail", "")):
        existing["detail"] = f"{existing['detail']}; {edge.detail}"


def _namespace_from_key(key: str) -> str | None:
    namespace = key.split("/", 1)[0]
    if namespace == "_cluster":
        return None
    return namespace
