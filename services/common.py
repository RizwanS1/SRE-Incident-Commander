from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from pydantic import BaseModel, ConfigDict, Field

_requests_instrumented = False
_memory_pressure_slots = asyncio.Semaphore(2)


class ChaosRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["off", "latency", "error", "memory"]
    latency_ms: int = Field(default=500, ge=1, le=5_000)
    memory_bytes: int = Field(default=16 * 1024 * 1024, ge=1, le=32 * 1024 * 1024)
    ttl_seconds: int = Field(default=60, ge=1, le=300)


class ChaosController:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._config = ChaosRequest(mode="off")
        self._expires_at = 0.0

    def configure(self, config: ChaosRequest) -> None:
        with self._lock:
            self._config = config
            self._expires_at = time.monotonic() + config.ttl_seconds

    def current(self) -> ChaosRequest:
        with self._lock:
            if self._config.mode != "off" and time.monotonic() >= self._expires_at:
                self._config = ChaosRequest(mode="off")
            return self._config


def _configure_telemetry(service: str) -> tuple[TracerProvider, MeterProvider]:
    resource = Resource.create(
        {"service.name": service, "service.namespace": "sre-incident-commander"}
    )
    tracer_provider = TracerProvider(resource=resource)
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").rstrip("/")
    metric_readers = []
    if otlp_endpoint:
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces"))
        )
        metric_readers.append(
            PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=f"{otlp_endpoint}/v1/metrics"),
                export_interval_millis=10_000,
            )
        )
    meter_provider = MeterProvider(resource=resource, metric_readers=metric_readers)
    return tracer_provider, meter_provider


def instrument_service(app: FastAPI, service: str) -> None:
    global _requests_instrumented
    tracer_provider, meter_provider = _configure_telemetry(service)
    FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)
    app.add_event_handler("shutdown", tracer_provider.shutdown)
    app.add_event_handler("shutdown", meter_provider.shutdown)
    if not _requests_instrumented:
        RequestsInstrumentor().instrument(tracer_provider=tracer_provider)
        _requests_instrumented = True
    meter = meter_provider.get_meter(f"sre-incident-commander.{service}")
    request_counter = meter.create_counter("app_requests", unit="1", description="HTTP requests")
    request_duration = meter.create_histogram(
        "app_request_duration", unit="s", description="HTTP request duration"
    )
    chaos = ChaosController()
    app.state.chaos = chaos

    @app.middleware("http")
    async def observe_request(request: Request, call_next):
        started = time.perf_counter()
        status_code = 500
        excluded_paths = {"/healthz", "/readyz", "/chaos"}
        try:
            if request.url.path not in excluded_paths:
                config = chaos.current()
                if config.mode == "latency":
                    await asyncio.sleep(config.latency_ms / 1000)
                elif config.mode == "error":
                    status_code = 503
                    return JSONResponse(
                        status_code=status_code,
                        content={"detail": f"{service} chaos: injected error"},
                    )
                elif config.mode == "memory":
                    async with _memory_pressure_slots:
                        pressure = bytearray(config.memory_bytes)
                        for offset in range(0, len(pressure), 4096):
                            pressure[offset] = 1
                        response = await call_next(request)
                        status_code = response.status_code
                        del pressure
                        return response

            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            if request.url.path not in excluded_paths:
                attributes = {
                    "service": service,
                    "method": request.method,
                    "status_code": str(status_code),
                }
                request_counter.add(1, attributes)
                request_duration.record(time.perf_counter() - started, attributes)


def register_chaos_route(app: FastAPI) -> None:
    @app.post("/chaos")
    async def configure_chaos(config: ChaosRequest) -> dict[str, object]:
        controller: ChaosController = app.state.chaos
        controller.configure(config)
        return {
            "mode": config.mode,
            "ttl_seconds": config.ttl_seconds,
            "limits": {"latency_ms": 5_000, "memory_bytes": 32 * 1024 * 1024},
        }
