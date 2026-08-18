from __future__ import annotations

import pytest

from impactgate.llm import FakeProvider


@pytest.fixture(autouse=True)
def _fake_llm_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never call a real LLM provider."""

    monkeypatch.setattr("impactgate.cli.build_provider", lambda _name=None: FakeProvider())
