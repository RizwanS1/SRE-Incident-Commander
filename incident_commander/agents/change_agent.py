from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from incident_commander.agents.schemas import ChangeInput, ChangeOutput, EvidenceRecord
from incident_commander.models import Evidence


class KubernetesChangeBackend(Protocol):
    def collect(self, alert: dict[str, object]) -> list[Evidence]: ...


class ChangeAgent:
    def __init__(self, backend: KubernetesChangeBackend) -> None:
        self.backend = backend

    def run(self, request: ChangeInput) -> ChangeOutput:
        started = datetime.now(UTC)
        evidence: list[EvidenceRecord] = []
        for service in [request.alert.service, *request.related_services]:
            source_items = self.backend.collect(
                {
                    "service": service,
                    "startsAt": request.alert.starts_at.isoformat(),
                    "endsAt": (request.alert.ends_at.isoformat() if request.alert.ends_at else ""),
                }
            )
            evidence.extend(
                EvidenceRecord(
                    evidence_id=f"changes-{service}-{item.evidence_id}",
                    agent="changes",
                    source="deployment" if item.source == "deployment" else item.source,
                    observed_at=self._timestamp(item.observed_at),
                    statement=item.statement[:12_000],
                    raw_value=item.value,
                    labels={"service": service},
                )
                for item in source_items
                if item.source in {"deployment", "event", "system"}
            )
        return ChangeOutput(
            status="complete" if evidence else "unavailable",
            started_at=started,
            completed_at=datetime.now(UTC),
            evidence=evidence,
            findings=[f"Collected {len(evidence)} rollout or change record(s)."],
        )

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
