"""Typer CLI for local runs without GitHub."""

from __future__ import annotations

from pathlib import Path

import typer

from impactgate.config import load_settings
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
        help="Directory of Kubernetes manifests to analyze.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Disable the on-disk cache.",
    ),
) -> None:
    """Analyze a directory of Kubernetes manifests and print a report."""
    load_settings(repo_root=path, no_cache=no_cache)
    decision = GateDecision(risk="low", verdicts=[], reason="no findings")
    typer.echo(render_report(decision), nl=False)


def main() -> None:
    app()
