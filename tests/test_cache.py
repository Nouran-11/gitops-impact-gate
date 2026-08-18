from __future__ import annotations

import asyncio
from pathlib import Path

from impactgate.cache.fingerprint import node_fingerprint
from impactgate.cache.store import CacheStore
from impactgate.cli import run_analysis
from impactgate.llm import FakeProvider

from tests.helpers import graph_from_yaml

MOUNTED = """
apiVersion: v1
kind: ConfigMap
metadata: {name: app-config, namespace: demo}
data: {FEATURE: off}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: checkout, namespace: demo}
spec:
  selector: {matchLabels: {app: checkout}}
  template:
    metadata: {labels: {app: checkout}}
    spec:
      volumes:
        - name: cfg
          configMap: {name: app-config}
      containers: [{name: app, image: nginx:1.25}]
"""

MOUNTED_CHANGED = MOUNTED.replace("FEATURE: off", "FEATURE: on")


def test_configmap_change_changes_workload_fingerprint() -> None:
    before = graph_from_yaml(MOUNTED)
    after = graph_from_yaml(MOUNTED_CHANGED)
    workload = "demo/Deployment/checkout"
    assert node_fingerprint(before, workload) != node_fingerprint(after, workload)


def test_unchanged_configmap_keeps_workload_fingerprint() -> None:
    left = graph_from_yaml(MOUNTED)
    right = graph_from_yaml(MOUNTED)
    workload = "demo/Deployment/checkout"
    assert node_fingerprint(left, workload) == node_fingerprint(right, workload)


def test_second_run_makes_zero_llm_calls(tmp_path: Path) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    _write_selector_break_pair(before_dir, after_dir)
    cache = CacheStore(tmp_path / ".impactgate-cache", enabled=True)
    first = FakeProvider()
    asyncio.run(
        run_analysis(
            after_dir,
            before_dir,
            "fake",
            cache=cache,
            provider=first,
        )
    )
    assert first.calls
    second = FakeProvider()
    asyncio.run(
        run_analysis(
            after_dir,
            before_dir,
            "fake",
            cache=cache,
            provider=second,
        )
    )
    assert second.calls == []
    assert cache.stats.llm_calls_made == 0
    assert cache.stats.llm_calls_saved > 0


def test_no_cache_does_not_reuse_llm(tmp_path: Path) -> None:
    before_dir = tmp_path / "before"
    after_dir = tmp_path / "after"
    _write_selector_break_pair(before_dir, after_dir)
    cache = CacheStore(tmp_path / ".impactgate-cache", enabled=False)
    first = FakeProvider()
    asyncio.run(run_analysis(after_dir, before_dir, "fake", cache=cache, provider=first))
    second = FakeProvider()
    asyncio.run(run_analysis(after_dir, before_dir, "fake", cache=cache, provider=second))
    assert second.calls


def _write_selector_break_pair(before_dir: Path, after_dir: Path) -> None:
    root = Path(__file__).resolve().parents[1] / "demo" / "manifests" / "selector-break"
    for target in (before_dir, after_dir):
        target.mkdir()
        for path in root.glob("*.yaml"):
            (target / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    text = (after_dir / "deployment.yaml").read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    seen_template = False
    rewritten: list[str] = []
    for line in lines:
        if "template:" in line:
            seen_template = True
        if seen_template and line.strip() == "app: checkout":
            rewritten.append(line.replace("app: checkout", "app: checkout-v2"))
            seen_template = False
            continue
        rewritten.append(line)
    (after_dir / "deployment.yaml").write_text("".join(rewritten), encoding="utf-8")
