"""Impact subgraph -> mermaid source."""

from __future__ import annotations

import re
from collections.abc import Sequence

from impactgate.graph.edges import is_virtual_key

PSEUDO_KINDS = frozenset({"File", "Kubernetes", "Image", "LabelSet", "MISSING"})
SKIP_LABELS = frozenset({"(no pods)"})


def from_paths(paths: Sequence[Sequence[str]]) -> str:
    """Render reverse-reachability paths as a Mermaid flowchart of real k8s resources."""
    lines = ["flowchart LR"]
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str]] = set()
    for path in paths:
        rendered = [item for item in path if is_rendered_key(item)]
        node_ids = [_node_id(item) for item in rendered]
        for item, node_id in zip(rendered, node_ids, strict=True):
            if node_id not in seen_nodes:
                lines.append(f'  {node_id}["{_escape(item)}"]')
                seen_nodes.add(node_id)
        for left, right in zip(node_ids, node_ids[1:], strict=False):
            edge = (left, right)
            if edge not in seen_edges:
                lines.append(f"  {left} --> {right}")
                seen_edges.add(edge)
    if len(lines) == 1:
        return ""
    return "\n".join(lines)


def is_rendered_key(key: str) -> bool:
    """True for real Kubernetes resource keys; false for scanner/virtual nodes."""
    if key in SKIP_LABELS:
        return False
    if is_virtual_key(key):
        return False
    parts = key.split("/")
    if len(parts) < 2:
        return False
    kind = parts[1] if len(parts) >= 3 else parts[0]
    return kind not in PSEUDO_KINDS and kind[:1].isupper()


def _node_id(key: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", key)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned


def _escape(label: str) -> str:
    return label.replace('"', "'")
