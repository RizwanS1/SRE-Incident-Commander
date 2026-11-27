from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Protocol

import requests

from incident_commander.agents.schemas import (
    EvidenceRecord,
    MetricsInput,
    MetricsOutput,
)
from incident_commander.collectors import redact_sensitive

DEPENDENCIES: dict[str, list[str]] = {
    "orders": ["payments", "inventory"],
    "payments": [],
    "inventory": [],
}


class MetricsBackend(Protocol):
    def query_range(
        self, expression: str, start: datetime, end: datetime, step_seconds: int
    ) -> list[dict[str, object]]: ...


class MetricsAgent:
    def __init__(self, backend: MetricsBackend) -> None:
        self.backend = backend

    def run(self, request: MetricsInput) -> MetricsOutput:
        started = datetime.now(UTC)
        alert = request.alert
        start, end = alert.time_bounds()
        start -= timedelta(minutes=5)
        end += timedelta(minutes=5)
        services = [alert.service, *DEPENDENCIES[alert.service]]
        evidence: list[EvidenceRecord] = []
        warnings: list[str] = []
        for service in services:
            for name, expression in self._queries(service):
                try:
                    samples = self.backend.query_range(expression, start, end, 30)
                except (requests.RequestException, ValueError) as error:
                    warnings.append(
                        f"{service} {name} query failed: {redact_sensitive(str(error))}"
                    )
                    continue
                if not samples:
                    warnings.append(f"No {name} samples were returned for {service}.")
                for index, sample in enumerate(samples):
                    observed = sample.get("timestamp")
                    value = sample.get("value")
                    raw_labels = sample.get("labels")
                    if (
                        not isinstance(observed, datetime)
                        or isinstance(value, bool)
                        or not isinstance(value, float | int)
                    ):
                        warnings.append(
                            f"Discarded malformed {name} sample for {service} at index {index}."
                        )
                        continue
                    if not math.isfinite(value):
                        warnings.append(
                            f"Discarded non-finite {name} sample for {service} at index {index}."
                        )
                        continue
                    if not isinstance(raw_labels, dict) or raw_labels.get("service") != service:
                        warnings.append(
                            f"Discarded {name} sample for {service} without a matching "
                            "raw service label."
                        )
                        continue
                    evidence.append(
                        EvidenceRecord(
                            evidence_id=f"metrics-{service}-{name}-{index}",
                            agent="metrics",
                            source="prometheus",
                            observed_at=observed,
                            statement=(
                                f"{self._display_name(name)} for {service} measured "
                                f"{float(value):.6f}."
                            ),
                            raw_value=float(value),
                            labels={
                                **{str(key): str(label) for key, label in raw_labels.items()},
                                "service": service,
                                "metric": name,
                            },
                        )
                    )
        return MetricsOutput(
            status="complete"
            if evidence and not warnings
            else "partial"
            if evidence
            else "unavailable",
            started_at=started,
            completed_at=datetime.now(UTC),
            evidence=evidence,
            findings=[
                f"Collected {len(evidence)} metric samples across {len(services)} service(s)."
            ],
            warnings=warnings,
        )

    @staticmethod
    def _display_name(metric: str) -> str:
        return {
            "error_ratio": "Error ratio",
            "availability": "Availability",
            "p95_latency_seconds": "p95 latency",
            "memory_limit_utilization": "Memory limit utilization",
            "cpu_limit_utilization": "CPU limit utilization",
        }[metric]

    @staticmethod
    def _queries(service: str) -> list[tuple[str, str]]:
        return [
            (
                "error_ratio",
                f'service:error_ratio:rate5m{{service="{service}"}}',
            ),
            (
                "availability",
                f'service:availability:ratio_rate5m{{service="{service}"}}',
            ),
            (
                "p95_latency_seconds",
                f'service:latency:p95_5m{{service="{service}"}}',
            ),
            (
                "memory_limit_utilization",
                "label_replace("
                "sum by (namespace, pod) (container_memory_working_set_bytes"
                f'{{namespace="sre",pod=~"{service}-.+"}})'
                " / on (namespace, pod) "
                "sum by (namespace, pod) (container_spec_memory_limit_bytes"
                f'{{namespace="sre",pod=~"{service}-.+"}}), '
                f'"service", "{service}", "pod", ".*")',
            ),
            (
                "cpu_limit_utilization",
                "label_replace("
                "sum by (namespace, pod) (rate(container_cpu_usage_seconds_total"
                f'{{namespace="sre",pod=~"{service}-.+"}}[5m]))'
                " / on (namespace, pod) "
                "sum by (namespace, pod) ("
                "container_spec_cpu_quota{"
                f'namespace="sre",pod=~"{service}-.+"}} / '
                "container_spec_cpu_period{"
                f'namespace="sre",pod=~"{service}-.+"}}), '
                f'"service", "{service}", "pod", ".*")',
            ),
        ]
