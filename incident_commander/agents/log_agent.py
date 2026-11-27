from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Protocol

from incident_commander.agents.schemas import EvidenceRecord, LogInput, LogOutput
from incident_commander.models import Evidence

_ERROR_PATTERN = re.compile(
    r"(?i)\b(error|exception|traceback|failed|failure|oomkilled|outofmemory|timeout|panic)\b"
)


class KubernetesLogBackend(Protocol):
    def collect(self, alert: dict[str, object]) -> list[Evidence]: ...


class LogAgent:
    def __init__(self, backend: KubernetesLogBackend) -> None:
        self.backend = backend

    def run(self, request: LogInput) -> LogOutput:
        started = datetime.now(UTC)
        services = [request.alert.service, *request.related_services]
        evidence: list[EvidenceRecord] = []
        patterns: list[str] = []
        for service in services:
            source_items = self.backend.collect(
                {
                    "service": service,
                    "startsAt": request.alert.starts_at.isoformat(),
                    "endsAt": (request.alert.ends_at.isoformat() if request.alert.ends_at else ""),
                }
            )
            for item in source_items:
                if item.source not in {"pod", "pod_log", "event", "system"}:
                    continue
                timestamp = self._timestamp(item.observed_at)
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"logs-{service}-{item.evidence_id}",
                        agent="logs",
                        source=item.source,
                        observed_at=timestamp,
                        statement=item.statement[:12_000],
                        raw_value=item.value,
                        labels={"service": service},
                    )
                )
                if item.source in {"pod_log", "event"}:
                    patterns.extend(
                        line.strip()[:500]
                        for line in item.statement.splitlines()
                        if _ERROR_PATTERN.search(line)
                    )
        unique_patterns = list(dict.fromkeys(patterns))[:50]
        return LogOutput(
            status="complete" if evidence else "unavailable",
            started_at=started,
            completed_at=datetime.now(UTC),
            evidence=evidence,
            findings=[
                f"Collected {len(evidence)} pod, log, event, or collection-status record(s).",
                f"Extracted {len(unique_patterns)} unique error-pattern line(s).",
            ],
            error_patterns=unique_patterns,
        )

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
