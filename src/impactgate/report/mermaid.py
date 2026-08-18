"""Impact subgraph -> mermaid source."""

from __future__ import annotations

import re
from collections.abc import Sequence


def from_paths(paths: Sequence[Sequence[str]]) -> str:
    """Render reverse-reachability paths as a Mermaid flowchart."""
    lines = ["flowchart LR"]
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()
    for path in paths:
        node_ids = [_node_id(item) for item in path]
        for item, node_id in zip(path, node_ids, strict=True):
            if node_id not in seen_nodes:
                lines.append(f'  {node_id}["{_escape(item)}"]')
                seen_nodes.add(node_id)
        for left, right in zip(node_ids, node_ids[1:], strict=False):
            edge = (left, right)
            if edge not in seen_edges:
                lines.append(f"  {left} --> {right}")
                seen_edges.add(edge)
    if len(lines) == 1:
        lines.append('  empty["no impact"]')
    return "\n".join(lines)


def _node_id(key: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", key)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned


def _escape(label: str) -> str:
    return label.replace('"', "'")
