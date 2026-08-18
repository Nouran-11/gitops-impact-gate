import pytest

from impactgate.llm import FakeProvider
from impactgate.metrics import REGISTRY, stop_http_server


@pytest.fixture(autouse=True)
def _fake_llm_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never call a real LLM provider."""

    monkeypatch.setattr(
        "impactgate.cli.build_provider",
        lambda _name=None, **_kwargs: FakeProvider(),
    )


@pytest.fixture(autouse=True)
def _reset_metrics() -> None:
    REGISTRY.reset()
    yield
    REGISTRY.reset()
    stop_http_server()
