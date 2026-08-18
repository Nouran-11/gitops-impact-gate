from __future__ import annotations

import os
from pathlib import Path

from pytest import MonkeyPatch

from impactgate.config import REPO_CONFIG_FILENAME, load_settings

_IMPACTGATE_ENV = (
    "IMPACTGATE_LLM_PROVIDER",
    "IMPACTGATE_OLLAMA_MODEL",
    "IMPACTGATE_CONTROLLER_ENABLED",
    "IMPACTGATE_NO_CACHE",
    "IMPACTGATE_WEBHOOK_SECRET",
    "IMPACTGATE_CACHE_DIR",
)


def _clear_impactgate_env(monkeypatch: MonkeyPatch) -> None:
    for key in _IMPACTGATE_ENV:
        monkeypatch.delenv(key, raising=False)
    for key in list(os.environ):
        if key.startswith("IMPACTGATE_"):
            monkeypatch.delenv(key, raising=False)


def test_defaults(monkeypatch: MonkeyPatch) -> None:
    _clear_impactgate_env(monkeypatch)
    settings = load_settings()
    assert settings.llm_provider == "gemini"
    assert settings.ollama_model == "llama3.1:8b"
    assert settings.controller_enabled is False
    assert settings.no_cache is False
    assert settings.cache_dir == ".impactgate-cache"
    assert settings.metrics_port == 8000


def test_repo_config_file(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    _clear_impactgate_env(monkeypatch)
    (tmp_path / REPO_CONFIG_FILENAME).write_text(
        "llm_provider: ollama\ncontroller_enabled: true\nollama_model: mistral:7b\n",
        encoding="utf-8",
    )
    settings = load_settings(repo_root=tmp_path)
    assert settings.llm_provider == "ollama"
    assert settings.ollama_model == "mistral:7b"
    assert settings.controller_enabled is True
    assert settings.repo_config_path == str(tmp_path / REPO_CONFIG_FILENAME)


def test_env_overrides_repo_file(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    (tmp_path / REPO_CONFIG_FILENAME).write_text("llm_provider: ollama\n", encoding="utf-8")
    monkeypatch.setenv("IMPACTGATE_LLM_PROVIDER", "groq")
    settings = load_settings(repo_root=tmp_path)
    assert settings.llm_provider == "groq"


def test_ollama_model_env(monkeypatch: MonkeyPatch) -> None:
    _clear_impactgate_env(monkeypatch)
    monkeypatch.setenv("IMPACTGATE_OLLAMA_MODEL", "llama3.1:8b")
    settings = load_settings()
    assert settings.ollama_model == "llama3.1:8b"
    monkeypatch.setenv("IMPACTGATE_OLLAMA_MODEL", "qwen2.5:7b")
    settings = load_settings()
    assert settings.ollama_model == "qwen2.5:7b"


def test_metrics_port_env(monkeypatch: MonkeyPatch) -> None:
    _clear_impactgate_env(monkeypatch)
    monkeypatch.setenv("IMPACTGATE_METRICS_PORT", "9090")
    settings = load_settings()
    assert settings.metrics_port == 9090


def test_cli_no_cache_flag(tmp_path: Path) -> None:
    settings = load_settings(repo_root=tmp_path, no_cache=True)
    assert settings.no_cache is True

