from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import networkx as nx

from impactgate.graph.builder import build_graph
from impactgate.graph.parser import parse_directory, parse_text
from impactgate.models import Resource


def resources_from_yaml(text: str) -> list[Resource]:
    result = parse_text(text, source_file="fixture.yaml")
    assert result.ok, result.errors
    return result.resources


def graph_from_yaml(text: str) -> nx.DiGraph[str]:
    return build_graph(resources_from_yaml(text))


def selector_break_graphs() -> tuple[nx.DiGraph[str], nx.DiGraph[str], list[str]]:
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    parsed = parse_directory(root)
    assert parsed.ok, parsed.errors
    before = build_graph(parsed.resources)
    after_resources: list[Resource] = []
    for resource in parsed.resources:
        if resource.ref.kind == "Deployment" and resource.ref.name == "checkout":
            spec = deepcopy(resource.spec)
            spec["spec"]["template"]["metadata"]["labels"]["app"] = "checkout-v2"
            after_resources.append(resource.model_copy(update={"spec": spec}))
        else:
            after_resources.append(resource)
    after = build_graph(after_resources)
    return before, after, ["deployment.yaml"]
