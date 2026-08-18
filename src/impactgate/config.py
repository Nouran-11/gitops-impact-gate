"""Settings loaded from a repo config file, then environment, then CLI flags."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_CONFIG_FILENAME = ".impactgate.yaml"


class Settings(BaseSettings):
    """Runtime settings. Environment variables use the IMPACTGATE_ prefix."""

    model_config = SettingsConfigDict(env_prefix="IMPACTGATE_", extra="ignore")

    llm_provider: str = "gemini"
    ollama_model: str = "llama3.1:8b"
    controller_enabled: bool = False
    no_cache: bool = False
    webhook_secret: str = ""
    cache_dir: str = ".impactgate-cache"
    repo_config_path: str | None = Field(default=None, exclude=True)


def _load_repo_config(repo_root: Path) -> dict[str, Any]:
    config_path = repo_root / REPO_CONFIG_FILENAME
    if not config_path.is_file():
        return {}
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        msg = f"{config_path} must contain a YAML mapping"
        raise ValueError(msg)
    return {str(key): value for key, value in loaded.items()}


def load_settings(
    *,
    repo_root: Path | None = None,
    no_cache: bool | None = None,
) -> Settings:
    """Merge defaults < repo file < env < CLI.

    Env vars win over the repo file so CI can override a checked-in config.
    """
    file_data: dict[str, Any] = {}
    config_path: str | None = None
    if repo_root is not None:
        file_data = _load_repo_config(repo_root)
        candidate = repo_root / REPO_CONFIG_FILENAME
        if candidate.is_file():
            config_path = str(candidate)

    # pydantic-settings treats init kwargs as higher precedence than env.
    # Apply file data first, then construct so env still overrides file.
    if file_data:
        with _patched_environ_from_file(file_data):
            settings = Settings()
    else:
        settings = Settings()

    if no_cache is True:
        settings.no_cache = True
    if config_path is not None:
        settings.repo_config_path = config_path
    return settings


def _patched_environ_from_file(file_data: dict[str, Any]) -> _EnvironPatch:
    """Expose file values as env vars only when the real env var is unset."""
    updates: dict[str, str] = {}
    for key, value in file_data.items():
        env_key = f"IMPACTGATE_{key.upper()}"
        if env_key in os.environ:
            continue
        if isinstance(value, bool):
            updates[env_key] = "true" if value else "false"
        elif value is None:
            continue
        else:
            updates[env_key] = str(value)
    return _EnvironPatch(updates)


class _EnvironPatch:
    def __init__(self, updates: dict[str, str]) -> None:
        self._updates = updates
        self._previous: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for key, value in self._updates.items():
            self._previous[key] = os.environ.get(key)
            os.environ[key] = value

    def __exit__(self, *_exc: object) -> None:
        for key, previous in self._previous.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
