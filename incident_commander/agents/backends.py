from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Protocol

import requests

from incident_commander.models import Evidence


class PrometheusMetricsBackend:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("PROMETHEUS_URL", "http://prometheus:9090")).rstrip(
            "/"
        )

    def query_range(
        self, expression: str, start: datetime, end: datetime, step_seconds: int
    ) -> list[dict[str, object]]:
        response = requests.get(
            f"{self.base_url}/api/v1/query_range",
            params={
                "query": expression,
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": step_seconds,
            },
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            raise ValueError(f"Prometheus returned status {payload.get('status')!r}.")
        samples: list[dict[str, object]] = []
        for series in payload["data"]["result"]:
            labels = series.get("metric", {})
            for timestamp, raw_value in series.get("values", []):
                samples.append(
                    {
                        "timestamp": datetime.fromtimestamp(float(timestamp), UTC),
                        "value": float(raw_value),
                        "labels": {str(key): str(value) for key, value in labels.items()},
                    }
                )
        return samples


class KubernetesLogSource(Protocol):
    def collect(self, alert: dict[str, object]) -> list[Evidence]: ...


class KubernetesChangeSource(KubernetesLogSource, Protocol):
    def collect_changes(self, alert: dict[str, object]) -> list[Evidence]: ...


class DynatraceMetricsBackend:
    """Adapter seam for a future Dynatrace implementation."""

    def query_range(
        self, expression: str, start: datetime, end: datetime, step_seconds: int
    ) -> list[dict[str, object]]:
        raise NotImplementedError(
            "Configure a Dynatrace API adapter before selecting this backend."
        )


class TraceBackend(Protocol):
    def find_spans(
        self, service: str, start: datetime, end: datetime
    ) -> list[dict[str, object]]: ...


class JaegerTraceBackend:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("JAEGER_URL", "http://jaeger:16686")).rstrip("/")

    def find_spans(self, service: str, start: datetime, end: datetime) -> list[dict[str, object]]:
        response = requests.get(
            f"{self.base_url}/api/traces",
            params={
                "service": service,
                "start": int(start.timestamp() * 1_000_000),
                "end": int(end.timestamp() * 1_000_000),
                "limit": 100,
                "lookback": "2h",
            },
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        spans: list[dict[str, object]] = []
        for trace in payload.get("data", []):
            processes = trace.get("processes", {})
            for span in trace.get("spans", []):
                tags = {
                    item.get("key"): item.get("value")
                    for item in span.get("tags", [])
                    if isinstance(item, dict)
                }
                process = processes.get(span.get("processID"), {})
                process_tags = {
                    item.get("key"): item.get("value")
                    for item in process.get("tags", [])
                    if isinstance(item, dict)
                }
                service_name = process.get("serviceName") or process_tags.get("service.name")
                timestamp = datetime.fromtimestamp(int(span.get("startTime", 0)) / 1_000_000, UTC)
                if not start <= timestamp <= end:
                    continue
                error = (
                    bool(tags.get("error"))
                    or str(tags.get("otel.status_code", "")).upper() == "ERROR"
                )
                spans.append(
                    {
                        "span_id": str(span.get("spanID", "unknown")),
                        "operation": str(span.get("operationName", "unknown")),
                        "service": str(service_name or "unknown"),
                        "trace_id": str(trace.get("traceID", "unknown")),
                        "duration_ms": float(span.get("duration", 0)) / 1000,
                        "status": "error" if error else "ok",
                        "timestamp": timestamp,
                    }
                )
        return spans


class KubernetesLogBackend:
    def __init__(self, collector: KubernetesLogSource) -> None:
        self.collector = collector

    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        return self.collector.collect(alert)


class KubernetesChangeBackend(KubernetesLogBackend):
    def __init__(self, collector: KubernetesChangeSource) -> None:
        self.collector = collector

    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        return self.collector.collect_changes(alert)
