from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class InvestigationCreate(BaseModel):
    case_code: str | None = Field(default=None, max_length=64)
    title: str = Field(min_length=2, max_length=200)
    hypothesis: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"]
    owner_user_id: int = Field(gt=0)
    due_at: str | None = Field(default=None, min_length=10, max_length=40)
    anomaly_ids: list[int] = Field(default_factory=list, max_length=200)


class InvestigationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=2, max_length=200)
    hypothesis: str | None = Field(default=None, max_length=2000)
    owner_user_id: int | None = Field(default=None, gt=0)
    due_at: str | None = Field(default=None, min_length=10, max_length=40)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    expected_version: int = Field(gt=0)


class EvidenceCreate(BaseModel):
    content: str = Field(min_length=2, max_length=4000)
    source_uri: str | None = Field(default=None, max_length=500)


class StepCreate(BaseModel):
    description: str = Field(min_length=2, max_length=500)
    due_at: str | None = Field(default=None, min_length=10, max_length=40)


class ScanRequest(BaseModel):
    window_hours: int = Field(default=24, gt=0, le=720)


class ScanJobCreate(BaseModel):
    window_hours: int = Field(default=24, gt=0, le=720)
    scan_token: str | None = Field(default=None, max_length=64)


class LinkConfirm(BaseModel):
    anomaly_ids: list[int] = Field(min_length=1, max_length=200)


class MeasureApply(BaseModel):
    measure: Literal["quarantine", "observe"]


class DispositionWrite(BaseModel):
    note: str = Field(min_length=2, max_length=2000)


class CloseRequestCreate(BaseModel):
    note: str = Field(default="", max_length=2000)


class ReleaseDecisionCreate(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=1000)


class DismissRequest(BaseModel):
    reason: str = Field(min_length=2, max_length=1000)
