"""Cache key computation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import networkx as nx

from impactgate import __version__
from impactgate.models import Resource
from impactgate.prompting import PROMPT_VERSION

SCANNER_VERSIONS = ("checkov", "trivy", "kube-linter")


class FingerprintError(RuntimeError):
    """Raised when a node fingerprint cannot be computed. The subgraph is uncacheable."""


def canonical_spec(spec: dict[str, Any]) -> str:
    return json.dumps(spec, sort_keys=True, default=str, separators=(",", ":"))


def content_hash(payload: str | bytes) -> str:
    data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def node_fingerprint(
    graph: nx.DiGraph[str],
    node: str,
    *,
    memo: dict[str, str] | None = None,
    visiting: set[str] | None = None,
) -> str:
    """SHA-256 of spec + transitive dependency fingerprints + prompt/tool/scanner versions."""
    cache = memo if memo is not None else {}
    if node in cache:
        return cache[node]
    in_progress = visiting if visiting is not None else set()
    if node in in_progress:
        return content_hash(f"cycle:{node}")
    in_progress.add(node)
    try:
        digest = _fingerprint_uncached(graph, node, cache, in_progress)
    except FingerprintError:
        raise
    except Exception as exc:
        raise FingerprintError(f"failed to fingerprint {node}: {exc}") from exc
    finally:
        in_progress.discard(node)
    cache[node] = digest
    return digest


def fingerprint_graph(graph: nx.DiGraph[str]) -> dict[str, str]:
    """Fingerprint every node. Raises FingerprintError if any node fails."""
    memo: dict[str, str] = {}
    for node in graph.nodes:
        node_fingerprint(graph, node, memo=memo)
    return memo


def _fingerprint_uncached(
    graph: nx.DiGraph[str],
    node: str,
    memo: dict[str, str],
    visiting: set[str],
) -> str:
    data = graph.nodes[node]
    resource = data.get("resource")
    if isinstance(resource, Resource):
        spec_blob = canonical_spec(resource.spec)
    else:
        spec_blob = canonical_spec(
            {
                "key": node,
                "kind": data.get("kind"),
                "missing": bool(data.get("missing")),
                "type": data.get("type"),
            }
        )
    dep_fps = [
        node_fingerprint(graph, dep, memo=memo, visiting=visiting)
        for dep in sorted(graph.successors(node))
    ]
    payload = "\n".join(
        [
            spec_blob,
            *dep_fps,
            PROMPT_VERSION,
            __version__,
            ",".join(SCANNER_VERSIONS),
        ]
    )
    return content_hash(payload)
