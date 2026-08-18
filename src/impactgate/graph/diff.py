"""Before/after graph comparison."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import networkx as nx

from impactgate.models import Resource


def resource_map(graph: nx.DiGraph[str]) -> dict[str, Resource]:
    resources: dict[str, Resource] = {}
    for node, data in graph.nodes(data=True):
        resource = data.get("resource")
        if isinstance(resource, Resource):
            resources[node] = resource
    return resources


def changed_nodes(
    before: nx.DiGraph[str],
    after: nx.DiGraph[str],
    changed_files: Sequence[str],
) -> set[str]:
    """Nodes whose spec changed, plus any resource defined in a changed file."""
    before_resources = resource_map(before)
    after_resources = resource_map(after)
    changed: set[str] = set()
    changed_file_set = set(changed_files)
    for key in set(before_resources) | set(after_resources):
        left = before_resources.get(key)
        right = after_resources.get(key)
        if left is None or right is None or left.spec != right.spec:
            changed.add(key)
    for key, resource in after_resources.items():
        if resource.source_file in changed_file_set:
            changed.add(key)
    return changed


def changed_files_between(before_dir: Path | None, after_dir: Path) -> list[str]:
    """Repo-relative YAML paths that differ between two snapshot directories."""
    after_files = _yaml_index(after_dir)
    if before_dir is None:
        return sorted(after_files)
    before_files = _yaml_index(before_dir)
    names = set(before_files) | set(after_files)
    changed: list[str] = []
    for name in sorted(names):
        if name not in before_files or name not in after_files:
            changed.append(name)
            continue
        if before_files[name] != after_files[name]:
            changed.append(name)
    return changed


def _yaml_index(root: Path) -> dict[str, str]:
    index: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}:
            index[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
    return index
