"""Provider protocol, factory, fallback, and fake provider."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Protocol

import httpx

LOGGER = logging.getLogger("impactgate.llm")


class Provider(Protocol):
    name: str

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str: ...


class ProviderError(Exception):
    """A provider failed a single attempt."""


class RateLimitError(ProviderError):
    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


class PermanentError(ProviderError):
    """Provider cannot succeed this run (missing credentials, etc.). Do not retry."""


class FakeProvider:
    """Deterministic provider for tests. Never makes network calls."""

    name = "fake"

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[str] = []

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        del max_tokens
        self.calls.append(prompt)
        if self.responses:
            return self.responses.pop(0)
        ids = re.findall(r"finding_id: (\S+)", prompt)
        rules = re.findall(r"  rule: (\S+)", prompt)
        paths = re.findall(r"  path: (.+)", prompt)
        verdicts = []
        for finding_id, rule, path in zip(ids, rules, paths, strict=False):
            verdicts.append(
                {
                    "finding_id": finding_id,
                    "severity": "high",
                    "explanation": (
                        f"{rule}: the Service selector matches no pods, so traffic "
                        f"through the Ingress stops reaching the workload. Path: {path}."
                    ),
                    "suggested_fix": None,
                    "confidence": 0.9,
                }
            )
        if not verdicts:
            verdicts.append(
                {
                    "finding_id": None,
                    "severity": "high",
                    "explanation": (
                        "The change leaves the Service selecting no pods, so traffic stops."
                    ),
                    "suggested_fix": None,
                    "confidence": 0.9,
                }
            )
        return json.dumps({"verdicts": verdicts})


class FallbackProvider:
    """Try each provider. Retry transients; skip permanent failures for the rest of the run."""

    name = "fallback"

    def __init__(self, providers: list[Provider], *, max_attempts: int = 3) -> None:
        self.providers = providers
        self.max_attempts = max_attempts
        self._unavailable: set[str] = set()

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        last_error: Exception | None = None
        for provider in self.providers:
            if provider.name in self._unavailable:
                continue
            for attempt in range(self.max_attempts):
                try:
                    return await provider.complete(prompt, max_tokens=max_tokens)
                except RateLimitError as exc:
                    last_error = exc
                    delay = exc.retry_after if exc.retry_after is not None else 2**attempt
                    LOGGER.warning("%s rate-limited; sleeping %.1fs", provider.name, delay)
                    await asyncio.sleep(delay)
                except Exception as exc:
                    last_error = exc
                    if _is_permanent(exc):
                        self._mark_unavailable(provider, exc)
                        break
                    LOGGER.warning("%s attempt %s failed: %s", provider.name, attempt + 1, exc)
                    if attempt + 1 < self.max_attempts:
                        await asyncio.sleep(2**attempt)
            else:
                LOGGER.warning("%s failed; trying next provider", provider.name)
        raise ProviderError(f"all providers failed: {last_error}")

    def _mark_unavailable(self, provider: Provider, exc: Exception) -> None:
        if provider.name in self._unavailable:
            return
        self._unavailable.add(provider.name)
        LOGGER.warning("%s unavailable: %s", provider.name, exc)


def retry_after_seconds(response: httpx.Response) -> float | None:
    header = response.headers.get("Retry-After")
    if header is None:
        return None
    try:
        return float(header)
    except ValueError:
        return None


def _is_permanent(exc: BaseException) -> bool:
    if isinstance(exc, PermanentError):
        return True
    if isinstance(exc, RateLimitError | httpx.TimeoutException | httpx.TransportError):
        return False
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code < 500 and exc.response.status_code != 429
    return "is not set" in str(exc).lower()


def build_provider(
    name: str | None = None,
    *,
    ollama_model: str | None = None,
) -> Provider:
    selected = (name or os.environ.get("IMPACTGATE_LLM_PROVIDER") or "gemini").lower()
    if selected in {"fake", "none"}:
        return FakeProvider()
    from impactgate.llm.gemini import GeminiProvider
    from impactgate.llm.groq import GroqProvider
    from impactgate.llm.ollama import OllamaProvider

    model = ollama_model or os.environ.get("IMPACTGATE_OLLAMA_MODEL") or "llama3.1:8b"
    catalog: dict[str, Provider] = {
        "gemini": GeminiProvider(),
        "groq": GroqProvider(),
        "ollama": OllamaProvider(model=model),
    }
    order = [selected, *[item for item in ("gemini", "groq", "ollama") if item != selected]]
    chain = [catalog[item] for item in order if item in catalog]
    return FallbackProvider(chain)
