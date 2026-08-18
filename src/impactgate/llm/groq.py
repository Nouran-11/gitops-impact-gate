"""Groq provider."""

from __future__ import annotations

import os

import httpx

from impactgate.llm.provider import RateLimitError, retry_after_seconds


class GroqProvider:
    name = "groq"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "llama-3.1-8b-instant",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("GROQ_API_KEY", "")
        self.model = model
        self.timeout = timeout

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        if not self.api_key:
            raise RuntimeError("GROQ_API_KEY is not set")
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": 0,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=payload,
            )
        if response.status_code == 429:
            raise RateLimitError(retry_after_seconds(response))
        response.raise_for_status()
        body = response.json()
        choices = body.get("choices") or []
        if not choices:
            raise RuntimeError("groq returned no choices")
        return str(choices[0].get("message", {}).get("content", ""))
