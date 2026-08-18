"""Blast radius traversal."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

import networkx as nx
from pydantic import BaseModel, Field

from impactgate.analysis.rules import run_integrity_checks
from impactgate.analysis.severity import severity_floor
from impactgate.cache.fingerprint import FingerprintError, fingerprint_graph
from impactgate.graph.diff import changed_nodes
from impactgate.graph.edges import is_virtual_key
from impactgate.models import Finding, GateDecision, Resource, Severity, Verdict, compute_finding_id

REVERSE_DEPTH = 5
NO_PODS = "(no pods)"


class ImpactResult(BaseModel):
    findings: list[Finding]
    changed_nodes: list[str]
    needs_human_review: bool = False
    parse_errors: list[str] = Field(default_factory=list)
    uncacheable: bool = False


def compute_impact(
    before: nx.DiGraph[str],
    after: nx.DiGraph[str],
    changed_files: list[str],
) -> ImpactResult:
    changed = sorted(changed_nodes(before, after, changed_files))
    raw = run_integrity_checks(after, before=before)
    findings = [enrich_finding(after, item) for item in raw]
    uncacheable = False
    try:
        fingerprints = fingerprint_graph(after)
        findings = [apply_node_fingerprint(item, fingerprints) for item in findings]
    except FingerprintError:
        uncacheable = True
    return ImpactResult(findings=findings, changed_nodes=changed, uncacheable=uncacheable)


def enrich_finding(graph: nx.DiGraph[str], finding: Finding) -> Finding:
    start = finding.resource.key()
    path = choose_path(graph, reverse_paths(graph, start))
    if finding.rule == "broken-selector" and (not path or path[-1] != NO_PODS):
        path = [*path, NO_PODS]
    exposed = path_is_exposed(graph, path)
    dangling_kind = _dangling_kind(finding)
    floor = severity_floor(
        finding.rule,
        externally_exposed=exposed,
        dangling_kind=dangling_kind,
    )
    return finding.model_copy(update={"path": path, "severity_floor": floor})


def apply_node_fingerprint(finding: Finding, fingerprints: dict[str, str]) -> Finding:
    digest = fingerprints.get(finding.resource.key(), "")
    finding_id = compute_finding_id(
        finding.rule, finding.resource.key(), finding.evidence, digest
    )
    return finding.model_copy(update={"id": finding_id})


def reverse_paths(
    graph: nx.DiGraph[str],
    start: str,
    depth: int = REVERSE_DEPTH,
) -> list[list[str]]:
    if start not in graph:
        return [[start]]
    completed: list[list[str]] = []

    def walk(node: str, chain: list[str]) -> None:
        if len(chain) - 1 >= depth:
            completed.append(list(reversed(chain)))
            return
        predecessors = [
            pred
            for pred in graph.predecessors(node)
            if pred not in chain and not is_virtual_key(pred)
        ]
        if not predecessors:
            completed.append(list(reversed(chain)))
            return
        for pred in predecessors:
            walk(pred, chain + [pred])

    walk(start, [start])
    return completed


def choose_path(graph: nx.DiGraph[str], paths: Sequence[list[str]]) -> list[str]:
    if not paths:
        return []
    exposed = [path for path in paths if path_is_exposed(graph, path)]
    pool = exposed or list(paths)
    return max(pool, key=lambda path: (len(path), path))


def path_is_exposed(graph: nx.DiGraph[str], path: Sequence[str]) -> bool:
    return any(is_externally_exposed(graph, node) for node in path)


def is_externally_exposed(graph: nx.DiGraph[str], node: str) -> bool:
    if node not in graph:
        return False
    data = graph.nodes[node]
    if data.get("kind") == "Ingress":
        return True
    if data.get("kind") != "Service":
        return False
    resource = data.get("resource")
    if not isinstance(resource, Resource):
        return False
    spec = resource.spec.get("spec")
    if not isinstance(spec, dict):
        return False
    service_type = spec.get("type", "ClusterIP")
    return service_type in {"LoadBalancer", "NodePort"}


def to_gate_decision(result: ImpactResult) -> GateDecision:
    if result.needs_human_review:
        detail = "; ".join(result.parse_errors) if result.parse_errors else "parse error"
        return GateDecision(
            risk="high",
            verdicts=[],
            reason=f"needs human review: {detail}",
        )
    if not result.findings:
        return GateDecision(risk="low", verdicts=[], reason="no findings")
    verdicts = [
        Verdict(
            finding_id=item.id,
            severity=item.severity_floor,
            explanation=_deterministic_explanation(item),
            suggested_fix=None,
            confidence=1.0,
        )
        for item in sorted(result.findings, key=lambda item: item.rule)
    ]
    return GateDecision(
        risk=_risk(result.findings),
        verdicts=verdicts,
        reason=_reason(result.findings),
    )


def _deterministic_explanation(finding: Finding) -> str:
    rendered_path = " → ".join(finding.path) if finding.path else finding.resource.key()
    return f"{finding.rule}: {finding.evidence}. Path: {rendered_path}"


def _risk(findings: Sequence[Finding]) -> Literal["low", "medium", "high"]:
    ranks = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }
    highest = max(item.severity_floor for item in findings)
    if ranks[highest] >= ranks[Severity.HIGH]:
        return "high"
    if highest == Severity.MEDIUM:
        return "medium"
    return "low"


def _reason(findings: Sequence[Finding]) -> str:
    rules = ", ".join(sorted({item.rule for item in findings}))
    return f"{len(findings)} new finding(s): {rules}"


def _dangling_kind(finding: Finding) -> str | None:
    if finding.rule != "dangling-reference":
        return None
    marker = "(missing "
    if marker not in finding.evidence:
        return None
    return finding.evidence.rsplit(marker, 1)[-1].rstrip(")")
