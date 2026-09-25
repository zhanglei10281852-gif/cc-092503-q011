from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
Measure = Literal["none", "quarantine", "observe"]


class InvestigationCreate(BaseModel):
    case_code: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=2, max_length=200)
    hypothesis: str = Field(default="", max_length=4000)
    severity: Severity = "medium"
    owner_user_id: int = Field(gt=0)
    due_at: str | None = Field(default=None, max_length=40)
    anomaly_ids: list[int] = Field(default_factory=list, max_length=500)


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=2, max_length=200)
    hypothesis: str | None = Field(default=None, max_length=4000)
    severity: Severity | None = None
    owner_user_id: int | None = Field(default=None, gt=0)
    due_at: str | None = Field(default=None, max_length=40)
    expected_version: int = Field(gt=0)


class CandidateQuery(BaseModel):
    seed_anomaly_id: int | None = Field(default=None, gt=0)
    seed_sample_id: int | None = Field(default=None, gt=0)
    batch_id: int | None = Field(default=None, gt=0)
    location_id: int | None = Field(default=None, gt=0)
    root_sample_id: int | None = Field(default=None, gt=0)
    occurred_from: str | None = Field(default=None, max_length=40)
    occurred_to: str | None = Field(default=None, max_length=40)
    window_hours: int = Field(default=72, ge=1, le=24 * 90)


class AnomalyLinkRequest(BaseModel):
    anomaly_ids: list[int] = Field(min_length=1, max_length=1000)


class AffectedConfirmItem(BaseModel):
    sample_id: int = Field(gt=0)
    measure: Measure = "none"


class AffectedConfirmRequest(BaseModel):
    items: list[AffectedConfirmItem] = Field(min_length=1, max_length=2000)


class MeasureApplyRequest(BaseModel):
    measure: Literal["quarantine", "observe"]
    sample_ids: list[int] = Field(default_factory=list, max_length=2000)


class ExplainRequest(BaseModel):
    note: str = Field(min_length=2, max_length=4000)


class EvidenceCreate(BaseModel):
    source_type: str = Field(min_length=2, max_length=100)
    source_reference: str = Field(default="", max_length=300)
    note: str = Field(default="", max_length=4000)
    idempotency_key: str | None = Field(default=None, max_length=120)


class ActionCreate(BaseModel):
    step_code: str = Field(min_length=2, max_length=64)
    title: str = Field(min_length=2, max_length=200)
    instruction: str = Field(default="", max_length=2000)
    assignee_user_id: int | None = Field(default=None, gt=0)
    due_at: str | None = Field(default=None, max_length=40)


class ActionComplete(BaseModel):
    result: str = Field(default="", max_length=2000)


class ClosureRequest(BaseModel):
    summary: str = Field(default="", max_length=4000)


class ClosureDecision(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=2000)
