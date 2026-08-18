from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from impactgate.config import REPO_CONFIG_FILENAME, load_settings


def test_defaults() -> None:
    settings = load_settings()
    assert settings.llm_provider == "gemini"
    assert settings.controller_enabled is False
    assert settings.no_cache is False
    assert settings.cache_dir == ".impactgate-cache"


def test_repo_config_file(tmp_path: Path) -> None:
    (tmp_path / REPO_CONFIG_FILENAME).write_text(
        "llm_provider: ollama\ncontroller_enabled: true\n",
        encoding="utf-8",
    )
    settings = load_settings(repo_root=tmp_path)
    assert settings.llm_provider == "ollama"
    assert settings.controller_enabled is True
    assert settings.repo_config_path == str(tmp_path / REPO_CONFIG_FILENAME)


def test_env_overrides_repo_file(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    (tmp_path / REPO_CONFIG_FILENAME).write_text("llm_provider: ollama\n", encoding="utf-8")
    monkeypatch.setenv("IMPACTGATE_LLM_PROVIDER", "groq")
    settings = load_settings(repo_root=tmp_path)
    assert settings.llm_provider == "groq"


def test_cli_no_cache_flag(tmp_path: Path) -> None:
    settings = load_settings(repo_root=tmp_path, no_cache=True)
    assert settings.no_cache is True
