"""Typer CLI for local runs without GitHub."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import networkx as nx
import typer

from impactgate.analysis.impact import ImpactResult, compute_impact, to_gate_decision
from impactgate.analysis.rules import drop_preexisting
from impactgate.cache.store import CacheStats, CacheStore, parse_directory_cached
from impactgate.config import load_settings
from impactgate.graph.builder import build_graph
from impactgate.graph.diff import changed_files_between
from impactgate.graph.parser import ParseResult, parse_directory
from impactgate.llm import Provider, build_provider, explain_findings
from impactgate.metrics import REGISTRY
from impactgate.models import Finding, GateDecision, Verdict
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
def controller(
    metrics_port: int | None = typer.Option(
        None,
        "--metrics-port",
        help="Port for GET /metrics (default IMPACTGATE_METRICS_PORT or 8000).",
    ),
    namespace: list[str] | None = typer.Option(
        None,
        "--namespace",
        "-n",
        help="Namespace to watch (repeatable). Defaults to demo.",
    ),
    all_namespaces: bool = typer.Option(
        False,
        "--all-namespaces",
        "-A",
        help="Watch every namespace (requires cluster-scoped RBAC).",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="DEBUG logs. Default is INFO (same as kopf run without -v).",
    ),
) -> None:
    """Watch the cluster and remediate managed workloads.

    Requires IMPACTGATE_CONTROLLER_ENABLED=true.

    This is the supported equivalent of
    `kopf run -m impactgate.controller.watcher --namespace demo --standalone`.
    """
    settings = load_settings()
    if not settings.controller_enabled:
        typer.echo(
            "Refusing to start: set IMPACTGATE_CONTROLLER_ENABLED=true",
            err=True,
        )
        raise typer.Exit(code=1)
    port = metrics_port if metrics_port is not None else settings.metrics_port
    import kopf

    from impactgate.controller.cluster import attach_kubernetes_client
    from impactgate.controller.watcher import RUNTIME, _register_kopf, reset_runtime
    from impactgate.metrics import start_http_server

    kopf.configure(verbose=verbose)
    bound = start_http_server(port)
    typer.echo(f"metrics listening on :{bound}/metrics")
    reset_runtime()
    attach_kubernetes_client(RUNTIME)
    _register_kopf()
    namespaces = tuple(namespace) if namespace else ("demo",)
    if all_namespaces:
        typer.echo("watching pods cluster-wide")
        kopf.run(
            clusterwide=True,
            standalone=True,
            registry=kopf.get_default_registry(),
        )
        return
    typer.echo(f"watching pods in namespace(s): {', '.join(namespaces)}")
    kopf.run(
        clusterwide=False,
        namespaces=namespaces,
        standalone=True,
        registry=kopf.get_default_registry(),
    )


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
    cache_root = Path(settings.cache_dir)
    if not cache_root.is_absolute():
        cache_root = path / cache_root
    cache = CacheStore(cache_root, enabled=not settings.no_cache)
    decision = asyncio.run(
        run_analysis(
            path,
            before,
            settings.llm_provider,
            cache=cache,
            ollama_model=settings.ollama_model,
        )
    )
    typer.echo(render_report(decision, cache_stats=cache.stats), nl=False)


async def run_analysis(
    after_dir: Path,
    before_dir: Path | None,
    llm_provider: str,
    *,
    cache: CacheStore | None = None,
    provider: Provider | None = None,
    ollama_model: str | None = None,
) -> GateDecision:
    started = time.perf_counter()
    try:
        decision = await _run_analysis(
            after_dir,
            before_dir,
            llm_provider,
            cache=cache,
            provider=provider,
            ollama_model=ollama_model,
        )
    finally:
        REGISTRY.record_analysis(time.perf_counter() - started)
    return decision


async def _run_analysis(
    after_dir: Path,
    before_dir: Path | None,
    llm_provider: str,
    *,
    cache: CacheStore | None = None,
    provider: Provider | None = None,
    ollama_model: str | None = None,
) -> GateDecision:
    if cache is not None:
        cache.stats = CacheStats()
    if cache is not None:
        after_parsed = parse_directory_cached(after_dir, cache)
    else:
        after_parsed = parse_directory(after_dir)
    if not after_parsed.ok:
        if cache is not None:
            cache.stats.uncacheable = True
        return _observe(_human_review(after_parsed))
    if before_dir is not None:
        if cache is not None:
            before_parsed = parse_directory_cached(before_dir, cache)
        else:
            before_parsed = parse_directory(before_dir)
    else:
        before_parsed = ParseResult()
    if before_dir is not None and not before_parsed.ok:
        if cache is not None:
            cache.stats.uncacheable = True
        return _observe(_human_review(before_parsed))
    after_graph = build_graph(after_parsed.resources)
    before_graph: nx.DiGraph[str] = (
        build_graph(before_parsed.resources) if before_dir is not None else nx.DiGraph()
    )
    files = changed_files_between(before_dir, after_dir)
    result = compute_impact(before_graph, after_graph, files)
    if result.uncacheable and cache is not None:
        cache.stats.uncacheable = True
    scanner_findings = await _scanner_findings(after_dir, before_dir, files, cache)
    merged = result.model_copy(update={"findings": [*result.findings, *scanner_findings]})
    decision = to_gate_decision(merged)
    if not merged.findings:
        return _observe(decision)
    llm = provider if provider is not None else build_provider(
        llm_provider, ollama_model=ollama_model
    )
    verdicts = await explain_findings(merged.findings, provider=llm, cache=cache)
    return _observe(_with_verdicts(decision, verdicts), merged.findings)


def _observe(decision: GateDecision, findings: list[Finding] | None = None) -> GateDecision:
    for item in findings or []:
        REGISTRY.record_finding(item.rule, item.severity_floor.value, item.origin)
    REGISTRY.record_gate(decision.risk)
    return decision


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


async def _scanner_findings(
    after_dir: Path,
    before_dir: Path | None,
    changed: list[str],
    cache: CacheStore | None,
) -> list[Finding]:
    after_findings = await run_all_scanners(_scan_targets(after_dir, changed), cache=cache)
    if before_dir is None:
        return after_findings
    before_findings = await run_all_scanners(_scan_targets(before_dir, changed), cache=cache)
    return drop_preexisting(after_findings, before_findings)


def _human_review(parsed: ParseResult) -> GateDecision:
    errors = [
        f"{item.source_file}:{item.source_line or '?'}: {item.message}" for item in parsed.errors
    ]
    return to_gate_decision(
        ImpactResult(findings=[], changed_nodes=[], needs_human_review=True, parse_errors=errors)
    )


def main() -> None:
    app()
