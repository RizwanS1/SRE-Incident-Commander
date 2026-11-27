from __future__ import annotations

import asyncio
import json
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from incident_commander.agents.change_agent import ChangeAgent
from incident_commander.agents.incident_report import render_incident_report
from incident_commander.agents.log_agent import LogAgent
from incident_commander.agents.metrics_agent import MetricsAgent
from incident_commander.agents.rca_agent import RcaAgent
from incident_commander.agents.remediation_agent import RemediationAgent
from incident_commander.agents.schemas import (
    AgentInput,
    AgentOutput,
    AlertContext,
    ChangeInput,
    LogInput,
    MetricsInput,
    RcaInput,
    RcaOutput,
    RemediationInput,
    RemediationSuggestion,
    TraceInput,
)
from incident_commander.agents.trace_agent import TraceAgent
from incident_commander.agents.validation import validate_agent_output
from incident_commander.collectors import redact_sensitive


class JsonLogger(Protocol):
    def record(
        self, agent: str, input_data: dict[str, object], output_data: dict[str, object]
    ) -> None: ...


class JsonlAgentLogger:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(os.getenv("AGENT_LOG_PATH", "artifacts/agent-events.jsonl"))
        self._lock = threading.Lock()

    def record(
        self, agent: str, input_data: dict[str, object], output_data: dict[str, object]
    ) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "agent": agent,
            "input": input_data,
            "output": output_data,
        }
        with self._lock, self.path.open("a", encoding="utf-8") as log_file:
            serialized = json.dumps(entry, sort_keys=True, default=str)
            log_file.write(redact_sensitive(serialized) + "\n")


class InvestigationOrchestrator:
    def __init__(
        self,
        metrics_agent: MetricsAgent,
        log_agent: LogAgent,
        change_agent: ChangeAgent,
        trace_agent: TraceAgent,
        rca_agent: RcaAgent,
        remediation_agent: RemediationAgent,
        logger: JsonLogger,
    ) -> None:
        self.metrics_agent = metrics_agent
        self.log_agent = log_agent
        self.change_agent = change_agent
        self.trace_agent = trace_agent
        self.rca_agent = rca_agent
        self.remediation_agent = remediation_agent
        self.logger = logger

    async def investigate(
        self, alert: AlertContext
    ) -> tuple[list[AgentOutput], RcaOutput, RemediationSuggestion, str]:
        related_services = {
            "orders": ["payments", "inventory"],
            "payments": [],
            "inventory": [],
        }[alert.service]
        agent_jobs: list[tuple[str, AgentInput, Callable[[AgentInput], AgentOutput]]] = [
            (
                "metrics",
                MetricsInput(alert=alert, related_services=related_services),
                lambda value: self.metrics_agent.run(
                    MetricsInput.model_validate(value.model_dump())
                ),
            ),
            (
                "logs",
                LogInput(alert=alert, related_services=related_services),
                lambda value: self.log_agent.run(LogInput.model_validate(value.model_dump())),
            ),
            (
                "changes",
                ChangeInput(alert=alert, related_services=related_services),
                lambda value: self.change_agent.run(ChangeInput.model_validate(value.model_dump())),
            ),
            (
                "traces",
                TraceInput(alert=alert, related_services=related_services),
                lambda value: self.trace_agent.run(TraceInput.model_validate(value.model_dump())),
            ),
        ]
        results = await asyncio.gather(
            *(
                asyncio.to_thread(self._run_and_log, name, agent_input, callback, alert)
                for name, agent_input, callback in agent_jobs
            )
        )
        outputs = [result for result in results if isinstance(result, AgentOutput)]
        if len(outputs) != len(agent_jobs):
            raise RuntimeError("One or more evidence agents returned an invalid output.")

        rca_input = RcaInput(alert=alert, agent_outputs=outputs)
        try:
            rca = await asyncio.to_thread(self.rca_agent.run, rca_input)
        except Exception as error:
            self.logger.record(
                "rca",
                rca_input.model_dump(mode="json"),
                {"status": "failed", "error": redact_sensitive(str(error))},
            )
            raise
        self.logger.record("rca", rca_input.model_dump(mode="json"), rca.model_dump(mode="json"))

        evidence = [item for result in outputs for item in result.evidence]
        remediation_input = RemediationInput(
            alert=alert, hypotheses=rca.hypotheses, evidence=evidence
        )
        try:
            remediation = await asyncio.to_thread(self.remediation_agent.run, remediation_input)
        except Exception as error:
            self.logger.record(
                "remediation",
                remediation_input.model_dump(mode="json"),
                {"status": "failed", "error": redact_sensitive(str(error))},
            )
            raise
        self.logger.record(
            "remediation",
            remediation_input.model_dump(mode="json"),
            remediation.model_dump(mode="json"),
        )
        report = render_incident_report(alert, outputs, rca, remediation)
        return outputs, rca, remediation, report

    def _run_and_log(
        self,
        name: str,
        agent_input: AgentInput,
        callback: Callable[[AgentInput], AgentOutput],
        alert: AlertContext,
    ) -> AgentOutput:
        self.logger.record(name, agent_input.model_dump(mode="json"), {"status": "started"})
        try:
            output = callback(agent_input)
            validated = validate_agent_output(output, alert)
        except Exception as error:
            self.logger.record(
                name,
                agent_input.model_dump(mode="json"),
                {"status": "failed", "error": redact_sensitive(str(error))},
            )
            raise
        self.logger.record(
            name,
            agent_input.model_dump(mode="json"),
            validated.model_dump(mode="json"),
        )
        return validated
