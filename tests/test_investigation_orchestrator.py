from __future__ import annotations

import asyncio
import json
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from incident_commander.agents.backends import (
    KubernetesChangeBackend,
    KubernetesLogBackend,
    TraceBackend,
)
from incident_commander.agents.change_agent import ChangeAgent
from incident_commander.agents.log_agent import LogAgent
from incident_commander.agents.metrics_agent import MetricsAgent
from incident_commander.agents.orchestrator import (
    InvestigationOrchestrator,
    JsonlAgentLogger,
)
from incident_commander.agents.rca_agent import RcaAgent
from incident_commander.agents.remediation_agent import RemediationAgent
from incident_commander.agents.schemas import AlertContext, MetricsInput
from incident_commander.agents.trace_agent import TraceAgent
from incident_commander.agents.validation import validate_metrics
from incident_commander.llm import MockHypothesisProvider
from incident_commander.models import Evidence

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "telemetry" / "orders-incident.json"


class FixtureMetricsBackend:
    def __init__(self, fixture: dict[str, Any], barrier: threading.Barrier) -> None:
        self.samples = fixture["metrics"]
        self.barrier = barrier
        self.first_call = True
        self.lock = threading.Lock()

    def query_range(
        self, expression: str, start: datetime, end: datetime, step_seconds: int
    ) -> list[dict[str, object]]:
        with self.lock:
            should_wait = self.first_call
            self.first_call = False
        if should_wait:
            self.barrier.wait(timeout=3)
        service_match = re.search(r'service="([^"]+)"', expression)
        service = service_match.group(1) if service_match else ""
        metric_name = next(
            (
                name
                for name in (
                    "error_ratio",
                    "availability",
                    "p95_latency_seconds",
                    "memory_limit_utilization",
                    "cpu_limit_utilization",
                )
                if name in expression
            ),
            "",
        )
        return [
            {
                "timestamp": datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")),
                "value": item["value"],
                "labels": {"service": service},
            }
            for item in self.samples
            if item["service"] == service and item["metric"] == metric_name
        ]


class FixtureKubernetesBackend:
    def __init__(
        self,
        records: list[dict[str, str]],
        barrier: threading.Barrier,
    ) -> None:
        self.records = records
        self.barrier = barrier
        self.lock = threading.Lock()
        self.waited = False

    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        with self.lock:
            should_wait = not self.waited
            self.waited = True
        if should_wait:
            self.barrier.wait(timeout=3)
        return [
            self._evidence(item)
            for item in self.records
            if item.get("service") == alert.get("service")
        ]

    def collect_changes(self, alert: dict[str, object]) -> list[Evidence]:
        with self.lock:
            should_wait = not self.waited
            self.waited = True
        if should_wait:
            self.barrier.wait(timeout=3)
        return [
            self._evidence(item)
            for item in self.records
            if item.get("service") == alert.get("service")
        ]

    @staticmethod
    def _evidence(item: dict[str, str]) -> Evidence:
        return Evidence(
            evidence_id=item["evidence_id"],
            source=item["source"],
            observed_at=item["observed_at"],
            statement=item["statement"],
        )


class FixtureTraceBackend(TraceBackend):
    def __init__(self, fixture: dict[str, Any], barrier: threading.Barrier) -> None:
        self.spans = fixture["spans"]
        self.barrier = barrier

    def find_spans(self, service: str, start: datetime, end: datetime) -> list[dict[str, object]]:
        self.barrier.wait(timeout=3)
        return [
            {
                **item,
                "timestamp": datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")),
            }
            for item in self.spans
        ]


class FixtureLogger(JsonlAgentLogger):
    def __init__(self, path: Path) -> None:
        super().__init__(path)


def test_recorded_telemetry_replay_runs_agents_in_parallel_and_cites_evidence(
    tmp_path: Path,
) -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    barrier = threading.Barrier(4)
    kubernetes_backend = FixtureKubernetesBackend(fixture["logs"], barrier)
    change_backend = FixtureKubernetesBackend(fixture["changes"], barrier)
    orchestrator = InvestigationOrchestrator(
        metrics_agent=MetricsAgent(FixtureMetricsBackend(fixture, barrier)),
        log_agent=LogAgent(KubernetesLogBackend(kubernetes_backend)),
        change_agent=ChangeAgent(KubernetesChangeBackend(change_backend)),
        trace_agent=TraceAgent(FixtureTraceBackend(fixture, barrier)),
        rca_agent=RcaAgent(MockHypothesisProvider()),
        remediation_agent=RemediationAgent(),
        logger=FixtureLogger(tmp_path / "agent-events.jsonl"),
    )
    alert = AlertContext.model_validate(fixture["alert"])

    outputs, rca, remediation, report = asyncio.run(orchestrator.investigate(alert))

    assert [item.agent for item in outputs] == ["metrics", "logs", "changes", "traces"]
    assert rca.hypotheses
    all_ids = {item.evidence_id for output in outputs for item in output.evidence}
    assert all(
        cited in all_ids for hypothesis in rca.hypotheses for cited in hypothesis.evidence_ids
    )
    assert any("error rate" in item.title.lower() for item in rca.hypotheses)
    evidence_agents = {
        evidence.agent
        for output in outputs
        for evidence in output.evidence
        if any(evidence.evidence_id in hypothesis.evidence_ids for hypothesis in rca.hypotheses)
    }
    assert evidence_agents == {"metrics", "logs", "changes", "traces"}
    assert outputs[3].slowest_span_id == "orders-span-failed"
    assert outputs[3].failing_span_id == "orders-span-failed"
    assert remediation.action == "none"
    assert remediation.command == ""
    assert "does not identify" in remediation.reasoning
    assert remediation.requires_human_approval is True
    assert "did not execute" in report
    assert "SLO impact" in report

    events = [
        json.loads(line)
        for line in (tmp_path / "agent-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {item["agent"] for item in events} == {
        "metrics",
        "logs",
        "changes",
        "traces",
        "rca",
        "remediation",
    }
    assert all("input" in item and "output" in item for item in events)


def test_metrics_validator_rejects_tampered_sample_value() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    barrier = threading.Barrier(1)
    agent = MetricsAgent(FixtureMetricsBackend(fixture, barrier))
    alert = AlertContext.model_validate(fixture["alert"])

    output = agent.run(MetricsInput(alert=alert))
    output.evidence[0].statement = "Error ratio for orders measured 0.000000."

    with pytest.raises(ValueError, match="differs from its raw value"):
        validate_metrics(output, alert)
