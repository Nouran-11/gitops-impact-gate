"""Expected JSON response schema."""

from __future__ import annotations

from pydantic import BaseModel, Field

from impactgate.models import Severity


class ModelVerdict(BaseModel):
    finding_id: str | None = None
    severity: Severity
    explanation: str
    suggested_fix: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class ModelBatch(BaseModel):
    verdicts: list[ModelVerdict]
