"""PyGithub wrapper."""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Protocol

from impactgate.cache.store import CacheStore
from impactgate.config import load_settings
from impactgate.models import GateDecision
from impactgate.report.markdown import COMMENT_MARKER, status_for_risk

LOGGER = logging.getLogger("impactgate.github")


class PullRequestPoster(Protocol):
    def upsert_comment(self, repo: str, pr_number: int, body: str) -> None: ...

    def set_check(self, repo: str, sha: str, risk: str) -> None: ...


class RecordingPoster:
    """In-memory poster for tests."""

    def __init__(self) -> None:
        self.comments: list[tuple[str, int, str]] = []
        self.checks: list[tuple[str, str, str]] = []

    def upsert_comment(self, repo: str, pr_number: int, body: str) -> None:
        self.comments.append((repo, pr_number, body))

    def set_check(self, repo: str, sha: str, risk: str) -> None:
        self.checks.append((repo, sha, status_for_risk(risk)))


class GitHubPoster:
    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN", "")

    def upsert_comment(self, repo: str, pr_number: int, body: str) -> None:
        from github import Github

        if not self.token:
            LOGGER.warning("GITHUB_TOKEN is not set; skipping PR comment")
            return
        client = Github(self.token)
        pull = client.get_repo(repo).get_pull(pr_number)
        for comment in pull.get_issue_comments():
            if COMMENT_MARKER in comment.body:
                comment.edit(body)
                return
        pull.create_issue_comment(body)

    def set_check(self, repo: str, sha: str, risk: str) -> None:
        from github import Github

        if not self.token:
            LOGGER.warning("GITHUB_TOKEN is not set; skipping status check")
            return
        conclusion = status_for_risk(risk)
        repository = Github(self.token).get_repo(repo)
        repository.create_check_run(
            name="impact-gate",
            head_sha=sha,
            status="completed",
            conclusion=conclusion,
            output={
                "title": f"Impact Gate: {risk}",
                "summary": f"Gate risk is {risk} (check conclusion: {conclusion}).",
            },
        )


def clone_url_with_token(url: str, token: str) -> str:
    if not token or not url.startswith("https://"):
        return url
    rest = url.removeprefix("https://")
    return f"https://x-access-token:{token}@{rest}"


def checkout_sha(url: str, sha: str, dest: Path, *, token: str = "") -> None:
    dest.mkdir(parents=True, exist_ok=True)
    authenticated = clone_url_with_token(url, token)
    if not (dest / ".git").exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", authenticated, str(dest)],
            check=True,
            capture_output=True,
            text=True,
        )
    subprocess.run(
        ["git", "fetch", "--depth", "1", "origin", sha],
        cwd=dest,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "checkout", "--force", sha],
        cwd=dest,
        check=True,
        capture_output=True,
        text=True,
    )


async def analyze_pull_request(payload: dict[str, Any]) -> GateDecision:
    from impactgate.cli import run_analysis

    pull = payload.get("pull_request") or {}
    repo = payload.get("repository") or {}
    clone_url = str(repo.get("clone_url") or "")
    full_name = str(repo.get("full_name") or "repo")
    base_sha = str((pull.get("base") or {}).get("sha") or "")
    head_sha = str((pull.get("head") or {}).get("sha") or "")
    settings = load_settings()
    token = os.environ.get("GITHUB_TOKEN", "")
    root = Path("/tmp/impactgate-clones") / full_name.replace("/", "_")
    before_dir = root / "base" / base_sha
    after_dir = root / "head" / head_sha
    checkout_sha(clone_url, base_sha, before_dir, token=token)
    checkout_sha(clone_url, head_sha, after_dir, token=token)
    cache_root = Path(settings.cache_dir)
    if not cache_root.is_absolute():
        cache_root = after_dir / cache_root
    cache = CacheStore(cache_root, enabled=not settings.no_cache)
    return await run_analysis(after_dir, before_dir, settings.llm_provider, cache=cache)
