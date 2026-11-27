from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    source: Literal["prometheus", "pod_log", "pod", "event", "deployment", "trace", "system"]
    observed_at: str
    statement: str = Field(min_length=1, max_length=12_000)
    value: float | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    explanation: str = Field(min_length=1, max_length=2_000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=10)


class AlertmanagerAlert(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str
    labels: dict[str, str]
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str = ""
    endsAt: str = ""
    fingerprint: str = ""


class AlertmanagerPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    status: str
    alerts: list[AlertmanagerAlert] = Field(default_factory=list)
    commonLabels: dict[str, str] = Field(default_factory=dict)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool
    approver: str = Field(min_length=1, max_length=120)
    service: Literal["orders", "payments", "inventory"]
    replicas: int | None = Field(default=None, ge=2, le=10)


class ResolutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2_000)
    corrective_actions: list[str] = Field(default_factory=list, max_length=20)
