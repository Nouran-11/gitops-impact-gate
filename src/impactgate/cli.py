"""Typer CLI for local runs without GitHub."""

from __future__ import annotations

import asyncio
from pathlib import Path

import networkx as nx
import typer

from impactgate.analysis.impact import ImpactResult, compute_impact, to_gate_decision
from impactgate.config import load_settings
from impactgate.graph.builder import build_graph
from impactgate.graph.diff import changed_files_between
from impactgate.graph.parser import ParseResult, parse_directory
from impactgate.llm import build_provider, explain_findings
from impactgate.models import GateDecision, Verdict
from impactgate.report.markdown import render_report
from impactgate.scanners import run_all_scanners

app = typer.Typer(
    name="impactgate",
    help="GitOps Impact Gate: relationship-aware review of Kubernetes manifests.",
    no_args_is_help=True,
)


@app.callback()
def _root() -> None:
    """GitOps Impact Gate: relationship-aware review of Kubernetes manifests."""


@app.command()
def analyze(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Directory of Kubernetes manifests to analyze (the after snapshot).",
    ),
    before: Path | None = typer.Option(
        None,
        "--before",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Optional before snapshot. Findings that already exist here are ignored.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable the on-disk cache.",
    ),
) -> None:
    """Analyze a directory of Kubernetes manifests and print a report."""
    settings = load_settings(repo_root=path, no_cache=no_cache)
    decision = asyncio.run(run_analysis(path, before, settings.llm_provider))
    typer.echo(render_report(decision), nl=False)


async def run_analysis(after_dir: Path, before_dir: Path | None, llm_provider: str) -> GateDecision:
    after_parsed = parse_directory(after_dir)
    if not after_parsed.ok:
        return _human_review(after_parsed)
    before_parsed = parse_directory(before_dir) if before_dir is not None else ParseResult()
    if before_dir is not None and not before_parsed.ok:
        return _human_review(before_parsed)
    after_graph = build_graph(after_parsed.resources)
    before_graph: nx.DiGraph[str] = (
        build_graph(before_parsed.resources) if before_dir is not None else nx.DiGraph()
    )
    files = changed_files_between(before_dir, after_dir)
    result = compute_impact(before_graph, after_graph, files)
    scanner_findings = await run_all_scanners(_scan_targets(after_dir, files))
    merged = result.model_copy(update={"findings": [*result.findings, *scanner_findings]})
    decision = to_gate_decision(merged)
    if not merged.findings:
        return decision
    verdicts = await explain_findings(merged.findings, provider=build_provider(llm_provider))
    return _with_verdicts(decision, verdicts)


def _with_verdicts(decision: GateDecision, verdicts: list[Verdict]) -> GateDecision:
    ranks = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    highest = max((ranks[item.severity.value] for item in verdicts), default=0)
    risk = decision.risk
    if highest >= 2:
        risk = "high"
    elif highest == 1:
        risk = "medium"
    return decision.model_copy(update={"verdicts": verdicts, "risk": risk})


def _scan_targets(after_dir: Path, changed: list[str]) -> list[Path]:
    targets: list[Path] = []
    for name in changed:
        path = after_dir / name
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}:
            targets.append(path)
    return targets


def _human_review(parsed: ParseResult) -> GateDecision:
    errors = [
        f"{item.source_file}:{item.source_line or '?'}: {item.message}" for item in parsed.errors
    ]
    return to_gate_decision(
        ImpactResult(findings=[], changed_nodes=[], needs_human_review=True, parse_errors=errors)
    )


def main() -> None:
    app()
