from datetime import UTC, datetime
from typing import Literal

from incident_commander.agents.remediation_agent import RemediationAgent
from incident_commander.agents.schemas import AlertContext, EvidenceRecord, RemediationInput
from incident_commander.models import Hypothesis


def _request(
    *,
    agent: Literal["metrics", "logs", "changes", "traces"],
    source: str,
    statement: str,
    labels: dict[str, str] | None = None,
    raw_value: float | None = None,
) -> RemediationInput:
    evidence = EvidenceRecord(
        evidence_id="evidence-1",
        agent=agent,
        source=source,
        observed_at=datetime(2026, 11, 27, tzinfo=UTC),
        statement=statement,
        raw_value=raw_value,
        labels=labels or {},
    )
    return RemediationInput(
        alert=AlertContext(
            incident_id="test-incident",
            alert_name="TestAlert",
            service="inventory",
            starts_at=datetime(2026, 11, 27, tzinfo=UTC),
        ),
        hypotheses=[
            Hypothesis(
                title="Evidence-backed test hypothesis",
                explanation="The cited evidence supports this test.",
                confidence=0.9,
                evidence_ids=[evidence.evidence_id],
            )
        ],
        evidence=[evidence],
    )


def test_error_ratio_alone_does_not_suggest_restart() -> None:
    request = _request(
        agent="metrics",
        source="prometheus",
        statement="Error ratio for inventory measured 1.000000.",
        labels={"metric": "error_ratio"},
        raw_value=1.0,
    )

    suggestion = RemediationAgent().run(request)

    assert suggestion.action == "none"
    assert suggestion.command == ""
    assert "does not identify" in suggestion.reasoning


def test_recent_rollout_suggests_rollback() -> None:
    request = _request(
        agent="changes",
        source="deployment",
        statement="Recent rollout for inventory: revision=12.",
    )

    suggestion = RemediationAgent().run(request)

    assert suggestion.action == "rollback"
    assert suggestion.command == "kubectl rollout undo deployment/inventory -n sre"


def test_resource_saturation_suggests_scale() -> None:
    request = _request(
        agent="metrics",
        source="prometheus",
        statement="CPU limit utilization for inventory measured 0.950000.",
        labels={"metric": "cpu_limit_utilization"},
        raw_value=0.95,
    )

    suggestion = RemediationAgent().run(request)

    assert suggestion.action == "scale"
    assert suggestion.command == "kubectl scale deployment/inventory --replicas=2 -n sre"


def test_process_failure_log_suggests_restart() -> None:
    request = _request(
        agent="logs",
        source="pod_log",
        statement="worker panic: unrecoverable runtime state",
    )

    suggestion = RemediationAgent().run(request)

    assert suggestion.action == "restart"
    assert suggestion.command == "kubectl rollout restart deployment/inventory -n sre"
