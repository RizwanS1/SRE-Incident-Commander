from datetime import UTC, datetime, timedelta

from incident_commander.agents.rca_agent import RcaAgent
from incident_commander.agents.schemas import (
    AlertContext,
    ChangeOutput,
    EvidenceRecord,
    LogOutput,
    MetricsOutput,
    RcaInput,
    TraceOutput,
)
from incident_commander.models import Evidence, Hypothesis


class RecordingProvider:
    def __init__(self) -> None:
        self.alert: dict[str, object] = {}
        self.evidence: list[Evidence] = []

    def rank(self, alert: dict[str, object], evidence: list[Evidence]) -> list[Hypothesis]:
        self.alert = alert
        self.evidence = evidence
        return []


def test_rca_limits_metrics_and_trace_samples_but_includes_agent_findings() -> None:
    now = datetime.now(UTC)
    metric_evidence = [
        EvidenceRecord(
            evidence_id=f"metric-{index}",
            agent="metrics",
            source="prometheus",
            observed_at=now + timedelta(seconds=index),
            statement=f"Error ratio for inventory measured {value}.",
            raw_value=value,
            labels={"service": "inventory", "metric": "error_ratio"},
        )
        for index, value in enumerate([0.1, 0.9, 0.2])
    ]
    trace_evidence = [
        EvidenceRecord(
            evidence_id=f"trace-{span_id}",
            agent="traces",
            source="trace",
            observed_at=now,
            statement=f"Span operation ({span_id}) took 1ms; status={status}.",
            raw_value=1.0,
            labels={"service": "inventory", "span_id": span_id, "status": status},
        )
        for span_id, status in (
            ("slow", "ok"),
            ("failed", "error"),
            ("other", "ok"),
        )
    ]
    agent_outputs = [
        MetricsOutput(
            status="complete",
            started_at=now,
            completed_at=now,
            evidence=metric_evidence,
            findings=["Observed changing inventory error ratio."],
        ),
        LogOutput(
            status="complete",
            started_at=now,
            completed_at=now,
            findings=["No Kubernetes logs available."],
            evidence=[
                EvidenceRecord(
                    evidence_id="log-status",
                    agent="logs",
                    source="system",
                    observed_at=now,
                    statement="Kubernetes evidence collection is disabled.",
                )
            ],
        ),
        ChangeOutput(
            status="complete",
            started_at=now,
            completed_at=now,
            findings=["No recent rollout found."],
        ),
        TraceOutput(
            status="complete",
            started_at=now,
            completed_at=now,
            evidence=trace_evidence,
            slowest_span_id="slow",
            failing_span_id="failed",
        ),
    ]
    provider = RecordingProvider()
    request = RcaInput(
        alert=AlertContext(
            incident_id="compact-rca",
            alert_name="InventoryErrors",
            service="inventory",
            starts_at=now,
        ),
        agent_outputs=agent_outputs,
    )

    RcaAgent(provider).run(request)

    evidence_ids = {item.evidence_id for item in provider.evidence}
    assert evidence_ids == {
        "metric-1",
        "metric-2",
        "log-status",
        "trace-slow",
        "trace-failed",
    }
    assert [item["agent"] for item in provider.alert["agent_findings"]] == [
        "metrics",
        "logs",
        "changes",
        "traces",
    ]
