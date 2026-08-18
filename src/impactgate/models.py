"""Shared pydantic models. Downstream packages depend on these; change carefully."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class EdgeKind(StrEnum):
    """Kinds of edges extracted from Kubernetes resource relationships."""

    SELECTS = "SELECTS"
    ROUTES_TO = "ROUTES_TO"
    MOUNTS_CONFIG = "MOUNTS_CONFIG"
    MOUNTS_SECRET = "MOUNTS_SECRET"
    ENV_FROM = "ENV_FROM"
    CLAIMS = "CLAIMS"
    RUNS_AS = "RUNS_AS"
    GRANTS = "GRANTS"
    SCALES = "SCALES"
    TARGETS = "TARGETS"
    IMAGE = "IMAGE"


class Severity(StrEnum):
    """Deterministic severity floor. The LLM may raise severity, never lower it."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ResourceRef(BaseModel):
    api_version: str
    kind: str
    name: str
    namespace: str | None = None

    def key(self) -> str:
        return f"{self.namespace or '_cluster'}/{self.kind}/{self.name}"


class Resource(BaseModel):
    ref: ResourceRef
    spec: dict[str, Any]  # full parsed manifest
    source_file: str  # repo-relative path
    source_line: int  # line where this document starts


class Edge(BaseModel):
    source: str  # ResourceRef.key()
    target: str
    kind: EdgeKind
    detail: str  # e.g. "selector app=checkout"


class Finding(BaseModel):
    id: str  # stable hash, see compute_finding_id
    origin: Literal["graph", "scanner"]
    rule: str  # e.g. "broken-selector" or "CKV_K8S_20"
    resource: ResourceRef
    path: list[str]  # chain of resource keys, for graph findings
    evidence: str  # the exact lines/values that triggered it
    severity_floor: Severity  # deterministic minimum, LLM may raise not lower


class Verdict(BaseModel):
    finding_id: str
    severity: Severity
    explanation: str  # plain English, from LLM
    suggested_fix: str | None
    confidence: float


class GateDecision(BaseModel):
    risk: Literal["low", "medium", "high"]
    verdicts: list[Verdict] = Field(default_factory=list)
    reason: str


def compute_finding_id(
    rule: str,
    resource_key: str,
    evidence: str,
    node_fingerprint: str = "",
) -> str:
    """SHA-256 of (rule, resource.key(), evidence, node_fingerprint)."""
    payload = f"{rule}|{resource_key}|{evidence}|{node_fingerprint}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
