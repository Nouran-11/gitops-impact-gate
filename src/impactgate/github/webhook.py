"""FastAPI webhook routes."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response

from impactgate.config import load_settings
from impactgate.github.client import GitHubPoster, PullRequestPoster
from impactgate.models import GateDecision
from impactgate.report.markdown import render_report

LOGGER = logging.getLogger("impactgate.github")

AnalyzeFn = Callable[[dict[str, Any]], Awaitable[GateDecision]]


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    return hmac.compare_digest(expected, header)


def create_app(
    *,
    secret: str | None = None,
    poster: PullRequestPoster | None = None,
    analyzer: AnalyzeFn | None = None,
) -> FastAPI:
    settings = load_settings()
    webhook_secret = secret if secret is not None else settings.webhook_secret
    github = poster if poster is not None else GitHubPoster()
    app = FastAPI(title="Impact Gate")

    @app.post("/webhook")
    async def webhook(request: Request, background: BackgroundTasks) -> Response:
        body = await request.body()
        signature = request.headers.get("X-Hub-Signature-256")
        if not verify_signature(webhook_secret, body, signature):
            raise HTTPException(status_code=401, detail="invalid signature")
        event = request.headers.get("X-GitHub-Event", "")
        try:
            payload: dict[str, Any] = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="invalid json") from exc
        if event != "pull_request" or payload.get("action") not in {"opened", "synchronize"}:
            return Response(status_code=200)
        background.add_task(
            _process_pull_request,
            payload,
            github,
            analyzer,
        )
        return Response(status_code=200)

    return app


async def _process_pull_request(
    payload: dict[str, Any],
    poster: PullRequestPoster,
    analyzer: AnalyzeFn | None,
) -> None:
    pull = payload.get("pull_request") or {}
    repo = (payload.get("repository") or {}).get("full_name")
    number = pull.get("number")
    sha = (pull.get("head") or {}).get("sha")
    if not isinstance(repo, str) or not isinstance(number, int) or not isinstance(sha, str):
        LOGGER.warning("pull_request payload missing repo/number/sha")
        return
    try:
        if analyzer is not None:
            decision = await analyzer(payload)
        else:
            from impactgate.github.client import analyze_pull_request

            decision = await analyze_pull_request(payload)
        body = render_report(decision)
        poster.upsert_comment(repo, number, body)
        poster.set_check(repo, sha, decision.risk)
    except Exception:
        LOGGER.exception("failed to process pull request %s#%s", repo, number)
        poster.set_check(repo, sha, "high")


app = create_app()
