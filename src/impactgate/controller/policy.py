"""RemediationPolicy CRD handling."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from impactgate.controller.actions import Action

DEFAULT_MEMORY_CEILING = "2Gi"


class RemediationPolicy(BaseModel):
    mode: Literal["dry-run", "enforce"] = "dry-run"
    min_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    allowed_actions: list[Action] = Field(default_factory=list)
    max_actions_per_hour: int = 2
    memory_bump_factor: float = 1.5
    memory_limit_ceiling: str = DEFAULT_MEMORY_CEILING

    @property
    def dry_run(self) -> bool:
        return self.mode != "enforce"


def default_policy() -> RemediationPolicy:
    """If no policy exists for a namespace: dry-run with no allowed actions."""
    return RemediationPolicy()


def policy_from_crd(spec: dict[str, object]) -> RemediationPolicy:
    allowed_raw = spec.get("allowedActions")
    allowed_list = allowed_raw if isinstance(allowed_raw, list) else []
    known = {item.value for item in Action}
    actions = [Action(item) for item in allowed_list if isinstance(item, str) and item in known]
    mode_raw = spec.get("mode", "dry-run")
    mode: Literal["dry-run", "enforce"] = "enforce" if mode_raw == "enforce" else "dry-run"
    return RemediationPolicy(
        mode=mode,
        min_confidence=_as_float(spec.get("minConfidence"), 0.8),
        allowed_actions=actions,
        max_actions_per_hour=_as_int(spec.get("maxActionsPerHour"), 2),
        memory_bump_factor=_as_float(spec.get("memoryBumpFactor"), 1.5),
        memory_limit_ceiling=str(spec.get("memoryLimitCeiling") or DEFAULT_MEMORY_CEILING),
    )


def _as_float(value: object, default: float) -> float:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return float(value)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _as_int(value: object, default: int) -> int:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default
