"""Bounded remediation enum, guardrails, and executors."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, Field

from impactgate.metrics import REGISTRY

LOGGER = logging.getLogger("impactgate.controller")
HEALTHY_FOR = timedelta(minutes=10)


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
    confidence: float = 1.0


class ReplicaSetRevision(BaseModel):
    name: str
    desired: int
    ready: int
    ready_since: datetime | None = None


class AuditRecord(BaseModel):
    workload: str
    evidence: str
    classification: Action
    action: Action
    outcome: str
    dry_run: bool
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PolicyView(Protocol):
    """Subset of RemediationPolicy needed by the executor (avoids import cycle)."""

    min_confidence: float
    allowed_actions: list[Action]
    max_actions_per_hour: int
    memory_bump_factor: float
    memory_limit_ceiling: str

    @property
    def dry_run(self) -> bool: ...


class ClusterClient(Protocol):
    def previous_logs(self, namespace: str, pod: str) -> str: ...

    def current_logs(self, namespace: str, pod: str) -> str: ...

    def pod_events(self, namespace: str, pod: str) -> list[str]: ...

    def owning_workload(self, namespace: str, pod: Mapping[str, Any]) -> str: ...

    def replicaset_history(self, namespace: str, workload: str) -> list[str]: ...

    def list_revisions(self, namespace: str, workload: str) -> list[ReplicaSetRevision]: ...

    def rollback(self, namespace: str, workload: str, revision: str) -> str: ...

    def current_memory_limit(self, namespace: str, workload: str) -> str: ...

    def bump_memory(self, namespace: str, workload: str, new_limit: str) -> str: ...

    def restart(self, namespace: str, workload: str) -> str: ...

    def scale_out(self, namespace: str, workload: str) -> str: ...

    def emit_event(self, namespace: str, workload: str, message: str) -> None: ...

    def record_audit(self, record: AuditRecord) -> None: ...


@dataclass
class CircuitBreaker:
    max_per_hour: int = 2
    _hits: dict[str, list[datetime]] = field(default_factory=lambda: defaultdict(list))

    def allow(self, workload: str, at: datetime | None = None) -> bool:
        now = at or datetime.now(UTC)
        recent = [stamp for stamp in self._hits[workload] if now - stamp <= timedelta(hours=1)]
        self._hits[workload] = recent
        return len(recent) < self.max_per_hour

    def record(self, workload: str, at: datetime | None = None) -> None:
        now = at or datetime.now(UTC)
        self._hits[workload].append(now)


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


def last_healthy_revision(
    revisions: list[ReplicaSetRevision],
    *,
    now: datetime | None = None,
) -> ReplicaSetRevision | None:
    """A revision is healthy only after all replicas have been ready for ≥10 minutes."""
    moment = now or datetime.now(UTC)
    eligible: list[ReplicaSetRevision] = []
    for revision in revisions:
        if revision.desired <= 0 or revision.ready != revision.desired:
            continue
        if revision.ready_since is None:
            continue
        if moment - revision.ready_since >= HEALTHY_FOR:
            eligible.append(revision)
    if not eligible:
        return None
    return max(eligible, key=lambda item: item.ready_since or moment)


def apply_guardrails(
    diagnosis: Diagnosis,
    action: Action,
    policy: PolicyView,
    *,
    revisions: list[ReplicaSetRevision],
    breaker: CircuitBreaker,
    now: datetime | None = None,
) -> Action:
    moment = now or datetime.now(UTC)
    chosen = action
    if diagnosis.confidence < policy.min_confidence:
        chosen = Action.ESCALATE
    if chosen == Action.ROLLBACK and last_healthy_revision(revisions, now=moment) is None:
        chosen = Action.ESCALATE
    if chosen != Action.ESCALATE and chosen not in policy.allowed_actions:
        chosen = Action.ESCALATE
    key = f"{diagnosis.namespace}/{diagnosis.workload}"
    if chosen != Action.ESCALATE and not breaker.allow(key, at=moment):
        chosen = Action.ESCALATE
    return chosen


def execute_action(
    diagnosis: Diagnosis,
    action: Action,
    policy: PolicyView,
    client: ClusterClient,
    *,
    breaker: CircuitBreaker | None = None,
    now: datetime | None = None,
    logger: logging.Logger = LOGGER,
) -> AuditRecord:
    moment = now or datetime.now(UTC)
    key = f"{diagnosis.namespace}/{diagnosis.workload}"
    revisions = client.list_revisions(diagnosis.namespace, diagnosis.workload)
    classified = action
    active_breaker = breaker if breaker is not None else CircuitBreaker()
    active_breaker.max_per_hour = policy.max_actions_per_hour
    guarded = apply_guardrails(
        diagnosis,
        classified,
        policy,
        revisions=revisions,
        breaker=active_breaker,
        now=moment,
    )
    dry_run = policy.dry_run
    outcome: str
    if dry_run:
        outcome = "dry-run"
        logger.info(
            "dry-run: would %s on %s (reason=%s, mode=%s, allowed=%s)",
            classified.value,
            key,
            diagnosis.reason,
            "dry-run",
            [item.value for item in policy.allowed_actions],
        )
    elif guarded == Action.ESCALATE:
        outcome = "escalated"
        logger.info("escalate %s; classified=%s", key, classified.value)
    else:
        outcome = _run_executor(client, diagnosis, guarded, policy, revisions, moment)
        active_breaker.record(key, at=moment)
        logger.info("executed %s on %s: %s", guarded.value, key, outcome)
    record = AuditRecord(
        workload=key,
        evidence=f"{diagnosis.reason}: {diagnosis.compressed_logs[:200]}",
        classification=classified,
        action=guarded,
        outcome=outcome,
        dry_run=dry_run,
        at=moment,
    )
    client.record_audit(record)
    client.emit_event(
        diagnosis.namespace,
        diagnosis.workload,
        f"impactgate {record.action}: {record.outcome}",
    )
    reported = classified if dry_run else guarded
    label = "dry-run" if dry_run else ("escalated" if guarded == Action.ESCALATE else "executed")
    REGISTRY.record_remediation(reported.value, label)
    return record


def _run_executor(
    client: ClusterClient,
    diagnosis: Diagnosis,
    action: Action,
    policy: PolicyView,
    revisions: list[ReplicaSetRevision],
    now: datetime,
) -> str:
    if action == Action.ROLLBACK:
        healthy = last_healthy_revision(revisions, now=now)
        if healthy is None:
            return "escalated: no healthy revision"
        return client.rollback(diagnosis.namespace, diagnosis.workload, healthy.name)
    if action == Action.BUMP_MEMORY:
        current = client.current_memory_limit(diagnosis.namespace, diagnosis.workload)
        new_limit = scaled_memory(current, policy.memory_bump_factor, policy.memory_limit_ceiling)
        return client.bump_memory(diagnosis.namespace, diagnosis.workload, new_limit)
    if action == Action.RESTART:
        return client.restart(diagnosis.namespace, diagnosis.workload)
    if action == Action.SCALE_OUT:
        return client.scale_out(diagnosis.namespace, diagnosis.workload)
    return "escalated"


def _looks_like_app_bug(logs: str) -> bool:
    return any(marker in logs for marker in _APP_BUG_MARKERS)


_BINARY_SUFFIXES: tuple[tuple[str, int], ...] = (
    ("Pi", 1024**5),
    ("Ti", 1024**4),
    ("Gi", 1024**3),
    ("Mi", 1024**2),
    ("Ki", 1024),
)
_DECIMAL_SUFFIXES: tuple[tuple[str, int], ...] = (
    ("P", 1000**5),
    ("T", 1000**4),
    ("G", 1000**3),
    ("M", 1000**2),
    ("K", 1000),
    ("k", 1000),
)


def parse_quantity(raw: str) -> int:
    """Parse a Kubernetes resource quantity into bytes (integer)."""
    text = raw.strip()
    for suffix, multiplier in _BINARY_SUFFIXES:
        if text.endswith(suffix):
            return int(float(text[: -len(suffix)]) * multiplier)
    for suffix, multiplier in _DECIMAL_SUFFIXES:
        if text.endswith(suffix):
            return int(float(text[: -len(suffix)]) * multiplier)
    return int(float(text))


def format_quantity(num: int) -> str:
    for suffix, multiplier in _BINARY_SUFFIXES:
        if num >= multiplier and num % multiplier == 0:
            return f"{num // multiplier}{suffix}"
    return str(num)


def scaled_memory(current: str, factor: float, ceiling: str) -> str:
    """Multiply a memory limit by factor, never exceeding the ceiling."""
    bumped = int(parse_quantity(current) * factor)
    cap = parse_quantity(ceiling)
    return format_quantity(min(bumped, cap))
