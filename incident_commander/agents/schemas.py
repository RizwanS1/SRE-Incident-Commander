from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from incident_commander.models import Hypothesis

AgentName = Literal["metrics", "logs", "changes", "traces", "rca", "remediation"]


class AlertContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=128)
    alert_name: str
    service: Literal["orders", "payments", "inventory"]
    starts_at: datetime
    ends_at: datetime | None = None
    summary: str = Field(default="", max_length=2_000)
    description: str = Field(default="", max_length=5_000)

    @field_validator("starts_at", "ends_at")
    @classmethod
    def timestamps_must_be_timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("Alert timestamps must include a timezone.")
        return value

    @model_validator(mode="after")
    def end_must_follow_start(self) -> AlertContext:
        if self.ends_at is not None and self.ends_at < self.starts_at:
            raise ValueError("Alert ends_at cannot be earlier than starts_at.")
        return self

    def time_bounds(self) -> tuple[datetime, datetime]:
        end = self.ends_at or datetime.now(UTC)
        return self.starts_at, end


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=200)
    agent: Literal["metrics", "logs", "changes", "traces"]
    source: str
    observed_at: datetime
    statement: str = Field(min_length=1, max_length=12_000)
    raw_value: float | str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class AgentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert: AlertContext
    related_services: list[str] = Field(default_factory=list)


class AgentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: AgentName
    status: Literal["complete", "partial", "unavailable"]
    started_at: datetime
    completed_at: datetime
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class MetricsInput(AgentInput):
    pass


class MetricsOutput(AgentOutput):
    agent: Literal["metrics"] = "metrics"


class LogInput(AgentInput):
    pass


class LogOutput(AgentOutput):
    agent: Literal["logs"] = "logs"
    error_patterns: list[str] = Field(default_factory=list)


class ChangeInput(AgentInput):
    pass


class ChangeOutput(AgentOutput):
    agent: Literal["changes"] = "changes"


class TraceInput(AgentInput):
    pass


class TraceOutput(AgentOutput):
    agent: Literal["traces"] = "traces"
    slowest_span_id: str | None = None
    failing_span_id: str | None = None


class RcaInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert: AlertContext
    agent_outputs: list[AgentOutput]


class RcaOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: Literal["rca"] = "rca"
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RemediationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert: AlertContext
    hypotheses: list[Hypothesis]
    evidence: list[EvidenceRecord]


class RemediationSuggestion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: Literal["remediation"] = "remediation"
    action: Literal["restart", "scale", "rollback", "none"]
    command: str
    reasoning: str
    risk: Literal["low", "medium", "high"]
    requires_human_approval: Literal[True] = True
