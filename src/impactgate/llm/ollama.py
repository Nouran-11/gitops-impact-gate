"""Ollama provider."""

from __future__ import annotations

import os

import httpx

from impactgate.llm.provider import RateLimitError, retry_after_seconds


class OllamaProvider:
    name = "ollama"

    def __init__(
        self,
        *,
        host: str | None = None,
        model: str = "llama3.1:8b",
        timeout: float = 30.0,
    ) -> None:
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        self.model = model
        self.timeout = timeout

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": 0},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.host}/api/generate", json=payload)
        if response.status_code == 429:
            raise RateLimitError(retry_after_seconds(response))
        response.raise_for_status()
        body = response.json()
        return str(body.get("response", ""))
