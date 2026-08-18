"""Bounded remediation enum and classifiers. Executors land in M8."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class Action(StrEnum):
    ROLLBACK = "rollback"
    BUMP_MEMORY = "bump_memory"
    RESTART = "restart"
    SCALE_OUT = "scale_out"
    ESCALATE = "escalate"


class Diagnosis(BaseModel):
    namespace: str
    pod: str
    workload: str
    reason: str
    compressed_logs: str
    events: list[str]
    managed: bool = False


_APP_BUG_MARKERS = (
    "traceback (most recent call last)",
    "exception:",
    "panic:",
    "fatal error",
    "application error",
)


def classify_failure(diagnosis: Diagnosis) -> Action:
    """Select one closed-enum action. The model never produces a command string."""
    reason = diagnosis.reason.lower()
    logs = diagnosis.compressed_logs.lower()
    if "imagepullbackoff" in reason or "errimagepull" in reason:
        return Action.ROLLBACK
    if "createcontainerconfigerror" in reason:
        return Action.ROLLBACK
    if "oomkilled" in reason or "oomkilled" in logs:
        return Action.BUMP_MEMORY
    if "crashloopbackoff" in reason and _looks_like_app_bug(logs):
        return Action.ESCALATE
    if "crashloopbackoff" in reason or "backoff" in reason:
        return Action.RESTART
    return Action.ESCALATE


def _looks_like_app_bug(logs: str) -> bool:
    return any(marker in logs for marker in _APP_BUG_MARKERS)
