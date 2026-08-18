"""Gemini provider."""

from __future__ import annotations

import os

import httpx

from impactgate.llm.provider import PermanentError, RateLimitError, retry_after_seconds


class GeminiProvider:
    name = "gemini"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "gemini-2.0-flash",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")
        self.model = model
        self.timeout = timeout

    async def complete(self, prompt: str, *, max_tokens: int = 1500) -> str:
        if not self.api_key:
            raise PermanentError("GEMINI_API_KEY is not set")
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, params={"key": self.api_key}, json=payload)
        if response.status_code == 429:
            raise RateLimitError(retry_after_seconds(response))
        response.raise_for_status()
        body = response.json()
        candidates = body.get("candidates") or []
        if not candidates:
            raise RuntimeError("gemini returned no candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        texts = [part.get("text", "") for part in parts if isinstance(part, dict)]
        return "".join(texts)
