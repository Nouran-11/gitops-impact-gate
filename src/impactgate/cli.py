"""Typer CLI for local runs without GitHub."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import typer

from impactgate.analysis.impact import ImpactResult, compute_impact, to_gate_decision
from impactgate.config import load_settings
from impactgate.graph.builder import build_graph
from impactgate.graph.diff import changed_files_between
from impactgate.graph.parser import ParseResult, parse_directory
from impactgate.models import GateDecision
from impactgate.report.markdown import render_report

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
    load_settings(repo_root=path, no_cache=no_cache)
    decision = _analyze(path, before)
    typer.echo(render_report(decision), nl=False)


def _analyze(after_dir: Path, before_dir: Path | None) -> GateDecision:
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
    return to_gate_decision(result)


def _human_review(parsed: ParseResult) -> GateDecision:
    errors = [
        f"{item.source_file}:{item.source_line or '?'}: {item.message}" for item in parsed.errors
    ]
    return to_gate_decision(
        ImpactResult(findings=[], changed_nodes=[], needs_human_review=True, parse_errors=errors)
    )


def main() -> None:
    app()
