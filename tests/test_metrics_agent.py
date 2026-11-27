from datetime import UTC, datetime
from math import nan

from incident_commander.agents.metrics_agent import MetricsAgent
from incident_commander.agents.schemas import AlertContext, MetricsInput


class NonFiniteMetricsBackend:
    def query_range(
        self, expression: str, start: datetime, end: datetime, step_seconds: int
    ) -> list[dict[str, object]]:
        assert start <= datetime.now(UTC) <= end
        assert step_seconds > 0
        if "error_ratio" in expression:
            return [
                {
                    "timestamp": datetime.now(UTC),
                    "value": nan,
                    "labels": {"service": "inventory"},
                }
            ]
        return []


def test_metrics_agent_discards_non_finite_samples() -> None:
    now = datetime.now(UTC)
    request = MetricsInput(
        alert=AlertContext(
            incident_id="non-finite-metric",
            alert_name="TestAlert",
            service="inventory",
            starts_at=now,
        )
    )

    output = MetricsAgent(NonFiniteMetricsBackend()).run(request)

    assert output.evidence == []
    assert output.status == "unavailable"
    assert any("non-finite error_ratio sample" in warning for warning in output.warnings)
