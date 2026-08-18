from __future__ import annotations

from pathlib import Path

REQUIRED_PATHS = [
    "src/impactgate/models.py",
    "src/impactgate/config.py",
    "src/impactgate/cli.py",
    "src/impactgate/graph/parser.py",
    "src/impactgate/graph/builder.py",
    "src/impactgate/graph/edges.py",
    "src/impactgate/graph/diff.py",
    "src/impactgate/analysis/impact.py",
    "src/impactgate/analysis/rules.py",
    "src/impactgate/analysis/severity.py",
    "src/impactgate/scanners/base.py",
    "src/impactgate/scanners/checkov.py",
    "src/impactgate/scanners/trivy.py",
    "src/impactgate/scanners/kubelinter.py",
    "src/impactgate/llm/provider.py",
    "src/impactgate/llm/gemini.py",
    "src/impactgate/llm/groq.py",
    "src/impactgate/llm/ollama.py",
    "src/impactgate/llm/prompts.py",
    "src/impactgate/llm/schema.py",
    "src/impactgate/prompting.py",
    "src/impactgate/cache/fingerprint.py",
    "src/impactgate/cache/store.py",
    "src/impactgate/report/markdown.py",
    "src/impactgate/report/mermaid.py",
    "src/impactgate/github/webhook.py",
    "src/impactgate/github/client.py",
    "src/impactgate/controller/watcher.py",
    "src/impactgate/controller/actions.py",
    "src/impactgate/controller/policy.py",
    "src/impactgate/controller/cluster.py",
    "demo/manifests/selector-break/deployment.yaml",
    "demo/kind-config.yaml",
    "deploy/crd.yaml",
    "deploy/policy.yaml",
    "deploy/rbac.yaml",
    "deploy/grafana-dashboard.json",
    "src/impactgate/metrics.py",
    "pyproject.toml",
    "AGENTS.md",
]


def test_required_layout_exists() -> None:
    root = Path(__file__).resolve().parents[1]
    missing = [path for path in REQUIRED_PATHS if not (root / path).is_file()]
    assert missing == []
