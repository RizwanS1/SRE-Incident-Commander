from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

import requests

from incident_commander.agents.schemas import EvidenceRecord, TraceInput, TraceOutput


class TraceBackend(Protocol):
    def find_spans(
        self, service: str, start: datetime, end: datetime
    ) -> list[dict[str, object]]: ...


class TraceAgent:
    def __init__(self, backend: TraceBackend) -> None:
        self.backend = backend

    def run(self, request: TraceInput) -> TraceOutput:
        started = datetime.now(UTC)
        alert = request.alert
        start, end = alert.time_bounds()
        warnings: list[str] = []
        try:
            spans = self.backend.find_spans(alert.service, start, end)
        except (requests.RequestException, ValueError) as error:
            spans = []
            warnings.append(f"Jaeger trace query failed: {error}")
        evidence: list[EvidenceRecord] = []
        slowest: tuple[float, str] | None = None
        failing_span_id: str | None = None
        for span in spans:
            span_id = str(span.get("span_id", "unknown"))
            operation = str(span.get("operation", "unknown"))
            duration_ms = float(span.get("duration_ms", 0))
            status = str(span.get("status", "unset"))
            timestamp = span.get("timestamp")
            observed = timestamp if isinstance(timestamp, datetime) else started
            statement = f"Span {operation} ({span_id}) took {duration_ms:.3f}ms; status={status}."
            evidence.append(
                EvidenceRecord(
                    evidence_id=f"traces-{span_id}",
                    agent="traces",
                    source="trace",
                    observed_at=observed,
                    statement=statement,
                    raw_value=duration_ms,
                    labels={
                        "span_id": span_id,
                        "status": status,
                        "service": str(span.get("service", "unknown")),
                        "trace_id": str(span.get("trace_id", "unknown")),
                    },
                )
            )
            if slowest is None or duration_ms > slowest[0]:
                slowest = (duration_ms, span_id)
            if status.lower() in {"error", "failed", "internal_error"}:
                failing_span_id = span_id
        return TraceOutput(
            status="complete" if evidence else "unavailable",
            started_at=started,
            completed_at=datetime.now(UTC),
            evidence=evidence,
            findings=[f"Inspected {len(evidence)} trace span(s) for {alert.service}."],
            slowest_span_id=slowest[1] if slowest else None,
            failing_span_id=failing_span_id,
            warnings=warnings
            or ([] if evidence else ["No trace spans were returned for the alert window."]),
        )
