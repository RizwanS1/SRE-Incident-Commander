from __future__ import annotations

import math
import re
from datetime import timedelta

from incident_commander.agents.schemas import (
    AgentOutput,
    AlertContext,
    ChangeOutput,
    LogOutput,
    MetricsOutput,
    TraceOutput,
)

_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


def validate_metrics(output: MetricsOutput, alert: AlertContext) -> MetricsOutput:
    start, end = alert.time_bounds()
    start -= timedelta(minutes=6)
    end += timedelta(minutes=6)
    allowed_services = {alert.service}
    from incident_commander.agents.metrics_agent import DEPENDENCIES

    allowed_services.update(DEPENDENCIES[alert.service])
    for item in output.evidence:
        if item.source != "prometheus" or item.raw_value is None:
            raise ValueError(f"Metrics evidence {item.evidence_id} lacks a Prometheus sample.")
        if not isinstance(item.raw_value, float) or not math.isfinite(item.raw_value):
            raise ValueError(f"Metrics evidence {item.evidence_id} has a non-finite value.")
        if item.observed_at < start or item.observed_at > end:
            raise ValueError(f"Metrics evidence {item.evidence_id} is outside the alert window.")
        if item.labels.get("service") not in allowed_services:
            raise ValueError(
                f"Metrics evidence {item.evidence_id} references an unrelated service."
            )
        numbers = _NUMBER.findall(item.statement)
        if not numbers or not any(
            math.isclose(float(number), item.raw_value, rel_tol=1e-5, abs_tol=1e-7)
            for number in numbers
        ):
            raise ValueError(f"Metrics evidence {item.evidence_id} differs from its raw value.")
    return output


def validate_logs(output: LogOutput) -> LogOutput:
    source_by_id = {item.evidence_id: item.statement for item in output.evidence}
    if len(source_by_id) != len(output.evidence):
        raise ValueError("Log Agent evidence IDs must be unique.")
    evidence_text = "\n".join(
        item.statement for item in output.evidence if item.source in {"pod_log", "event"}
    )
    for pattern in output.error_patterns:
        if pattern not in evidence_text:
            raise ValueError(
                "Log Agent reported an error pattern absent from raw log/event evidence."
            )
    return output


def validate_changes(output: ChangeOutput) -> ChangeOutput:
    if len({item.evidence_id for item in output.evidence}) != len(output.evidence):
        raise ValueError("Change Agent evidence IDs must be unique.")
    if any(item.source not in {"deployment", "event", "system"} for item in output.evidence):
        raise ValueError("Change Agent returned an unsupported evidence source.")
    return output


def validate_traces(output: TraceOutput, alert: AlertContext) -> TraceOutput:
    spans = {item.labels.get("span_id"): item for item in output.evidence}
    if len(spans) != len(output.evidence):
        raise ValueError("Trace Agent span IDs must be unique.")
    for item in output.evidence:
        if item.source != "trace" or not isinstance(item.raw_value, float):
            raise ValueError(f"Trace evidence {item.evidence_id} is not a raw Jaeger span.")
        if not math.isfinite(item.raw_value) or item.raw_value < 0:
            raise ValueError(f"Trace evidence {item.evidence_id} has an invalid duration.")
        if not any(
            math.isclose(float(number), item.raw_value, rel_tol=1e-5, abs_tol=1e-3)
            for number in _NUMBER.findall(item.statement)
        ):
            raise ValueError(f"Trace evidence {item.evidence_id} differs from its raw span.")
    if output.slowest_span_id and output.slowest_span_id not in spans:
        raise ValueError("Trace Agent slowest span is absent from raw trace evidence.")
    if output.failing_span_id and output.failing_span_id not in spans:
        raise ValueError("Trace Agent failing span is absent from raw trace evidence.")
    if output.slowest_span_id and output.evidence:
        measured_slowest = max(output.evidence, key=lambda item: float(item.raw_value or 0))
        if output.slowest_span_id != measured_slowest.labels.get("span_id"):
            raise ValueError("Trace Agent selected a span that is not the slowest raw span.")
    if output.failing_span_id and spans[output.failing_span_id].labels.get("status") != "error":
        raise ValueError("Trace Agent failing span is not marked as an error in the raw span.")
    start, end = alert.time_bounds()
    if any(item.observed_at < start or item.observed_at > end for item in output.evidence):
        raise ValueError("Trace evidence is outside the alert time window.")
    return output


def validate_agent_output(output: AgentOutput, alert: AlertContext) -> AgentOutput:
    if isinstance(output, MetricsOutput):
        return validate_metrics(output, alert)
    if isinstance(output, LogOutput):
        return validate_logs(output)
    if isinstance(output, ChangeOutput):
        return validate_changes(output)
    if isinstance(output, TraceOutput):
        return validate_traces(output, alert)
    raise TypeError(f"Unsupported evidence agent output: {type(output).__name__}")
