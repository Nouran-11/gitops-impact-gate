from __future__ import annotations

from pathlib import Path

from impactgate.graph.parser import parse_directory, parse_text


def test_parse_text_tracks_document_start_lines() -> None:
    text = """apiVersion: v1
kind: ConfigMap
metadata:
  name: first
  namespace: demo
---
apiVersion: v1
kind: Secret
metadata:
  name: second
  namespace: demo
"""
    result = parse_text(text, source_file="app.yaml")
    assert result.ok
    assert [item.ref.kind for item in result.resources] == ["ConfigMap", "Secret"]
    assert result.resources[0].source_line == 1
    assert result.resources[1].source_line == 6
    assert result.resources[0].source_file == "app.yaml"


def test_parse_text_fails_closed_on_invalid_yaml() -> None:
    result = parse_text("apiVersion: [\n", source_file="bad.yaml")
    assert not result.ok
    assert result.resources == []
    assert "YAML parse error" in result.errors[0].message


def test_parse_text_fails_closed_on_missing_name() -> None:
    result = parse_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n",
        source_file="anon.yaml",
    )
    assert not result.ok
    assert result.errors[0].message == "missing metadata.name"


def test_parse_directory_skips_non_yaml_and_config(tmp_path: Path) -> None:
    (tmp_path / "ok.yaml").write_text(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ok\n",
        encoding="utf-8",
    )
    (tmp_path / "notes.txt").write_text("not yaml\n", encoding="utf-8")
    (tmp_path / ".impactgate.yaml").write_text("llm_provider: ollama\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "svc.yml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n  namespace: demo\n",
        encoding="utf-8",
    )
    result = parse_directory(tmp_path)
    assert result.ok
    keys = sorted(item.ref.key() for item in result.resources)
    assert keys == ["_cluster/ConfigMap/ok", "demo/Service/web"]


def test_parse_directory_cluster_scoped_key() -> None:
    result = parse_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: admin\n",
        source_file="rbac.yaml",
    )
    assert result.ok
    assert result.resources[0].ref.key() == "_cluster/ClusterRole/admin"
