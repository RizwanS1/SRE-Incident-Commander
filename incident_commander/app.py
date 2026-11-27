from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Query
from kubernetes.client.exceptions import ApiException
from starlette.concurrency import run_in_threadpool
from starlette.responses import FileResponse, PlainTextResponse
from starlette.staticfiles import StaticFiles

from incident_commander.agents.backends import (
    JaegerTraceBackend,
    KubernetesChangeBackend,
    KubernetesLogBackend,
    PrometheusMetricsBackend,
)
from incident_commander.agents.change_agent import ChangeAgent
from incident_commander.agents.incident_report import (
    incident_report_path,
    write_incident_report,
)
from incident_commander.agents.log_agent import LogAgent
from incident_commander.agents.metrics_agent import MetricsAgent
from incident_commander.agents.orchestrator import (
    InvestigationOrchestrator,
    JsonlAgentLogger,
)
from incident_commander.agents.rca_agent import RcaAgent
from incident_commander.agents.remediation_agent import RemediationAgent
from incident_commander.agents.schemas import (
    AgentOutput,
    AlertContext,
    RcaOutput,
    RemediationSuggestion,
)
from incident_commander.agents.trace_agent import TraceAgent
from incident_commander.collectors import KubernetesEvidenceCollector, redact_sensitive
from incident_commander.llm import create_provider
from incident_commander.models import (
    AlertmanagerPayload,
    ApprovalRequest,
    Evidence,
    Hypothesis,
    ResolutionRequest,
)
from incident_commander.postmortem import generate_postmortem

app = FastAPI(title="SRE Incident Commander", version="1.0.0")
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
kubernetes = KubernetesEvidenceCollector()
orchestrator = InvestigationOrchestrator(
    metrics_agent=MetricsAgent(PrometheusMetricsBackend()),
    log_agent=LogAgent(KubernetesLogBackend(kubernetes)),
    change_agent=ChangeAgent(KubernetesChangeBackend(kubernetes)),
    trace_agent=TraceAgent(JaegerTraceBackend()),
    rca_agent=RcaAgent(create_provider()),
    remediation_agent=RemediationAgent(),
    logger=JsonlAgentLogger(),
)
incidents: dict[str, IncidentRecord] = {}
_audit_lock = threading.Lock()


@dataclass(slots=True)
class IncidentRecord:
    alert: dict[str, object]
    evidence: list[Evidence]
    hypotheses: list[Hypothesis]
    received_at: str
    agent_outputs: list[AgentOutput]
    rca: RcaOutput
    remediation: RemediationSuggestion
    report_path: Path


def _audit(
    action: str,
    service: str,
    approver: str,
    outcome: str,
    details: dict[str, object] | None = None,
) -> None:
    path = Path(os.getenv("AUDIT_LOG_PATH", "artifacts/audit.jsonl"))
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "action": action,
        "service": service,
        "approver": approver,
        "outcome": outcome,
        "details": details or {},
    }
    with _audit_lock, path.open("a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(record, sort_keys=True) + "\n")


def _incident_fingerprint(value: str, alert: dict[str, object]) -> str:
    if value:
        return value
    encoded = json.dumps(alert, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _report_code_value(lines: list[str], prefix: str) -> str:
    line = next((item for item in lines if item.startswith(prefix)), "")
    if "`" not in line:
        return ""
    return line.split("`", 2)[1]


def _make_postmortem(
    fingerprint: str,
    incident: IncidentRecord,
    summary: str,
    actions: list[str],
    resolved_at: str | None = None,
) -> Path:
    return generate_postmortem(
        fingerprint=fingerprint,
        alert=incident.alert,
        received_at=incident.received_at,
        resolved_at=resolved_at or datetime.now(UTC).isoformat(),
        evidence=incident.evidence,
        hypotheses=incident.hypotheses,
        resolution_summary=summary,
        corrective_actions=actions,
        output_dir=Path(os.getenv("POSTMORTEM_DIR", "artifacts/postmortems")),
    )


def _legacy_evidence(outputs: list[AgentOutput]) -> list[Evidence]:
    records: list[Evidence] = []
    for output in outputs:
        for item in output.evidence:
            if output.agent == "metrics":
                source = "prometheus"
            elif output.agent == "traces":
                source = "trace"
            else:
                source = item.source
            records.append(
                Evidence(
                    evidence_id=item.evidence_id,
                    source=source,
                    observed_at=item.observed_at.isoformat(),
                    statement=item.statement,
                    value=item.raw_value if isinstance(item.raw_value, float) else None,
                    labels=item.labels,
                )
            )
    return records


def _alert_context(
    alert: dict[str, object], incident_id: str, annotations: dict[str, str]
) -> AlertContext:
    try:
        starts_at = datetime.fromisoformat(str(alert.get("startsAt", "")).replace("Z", "+00:00"))
        ends_raw = str(alert.get("endsAt", ""))
        ends_at = (
            datetime.fromisoformat(ends_raw.replace("Z", "+00:00"))
            if ends_raw and not ends_raw.startswith("0001-01-01")
            else None
        )
        return AlertContext(
            incident_id=incident_id,
            alert_name=str(alert.get("alertname", "Unknown alert")),
            service=str(alert.get("service", "")),
            starts_at=starts_at,
            ends_at=ends_at,
            summary=redact_sensitive(annotations.get("summary", "")),
            description=redact_sensitive(annotations.get("description", "")),
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=422, detail=f"Alert timestamps or labels are invalid: {error}"
        ) from error


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/capabilities")
async def get_capabilities() -> dict[str, bool]:
    kubernetes_available = kubernetes.apps_api is not None
    approval_configured = bool(os.getenv("APPROVAL_TOKEN", ""))
    return {
        "kubernetes_available": kubernetes_available,
        "approval_configured": approval_configured,
        "runbooks_available": kubernetes_available and approval_configured,
    }


@app.get("/api/incidents")
async def list_incidents() -> dict[str, list[dict[str, object]]]:
    report_dir = Path(os.getenv("INCIDENT_REPORT_DIR", "artifacts/incidents"))
    summaries: dict[str, dict[str, object]] = {}
    for fingerprint, incident in incidents.items():
        summaries[fingerprint] = {
            "incident_id": fingerprint,
            "alert_name": str(incident.alert.get("alertname", "Incident")),
            "service": str(incident.alert.get("service", "unknown")),
            "summary": str(incident.alert.get("annotations", {}).get("summary", "")),
            "received_at": incident.received_at,
            "status": "analyzed",
            "hypotheses": [item.model_dump() for item in incident.hypotheses],
            "remediation": incident.remediation.model_dump(),
            "agent_statuses": [
                {"agent": output.agent, "status": output.status}
                for output in incident.agent_outputs
            ],
        }

    if report_dir.is_dir():
        for report_path in report_dir.glob("*.md"):
            if report_path.stem in summaries:
                continue
            lines = report_path.read_text(encoding="utf-8").splitlines()
            title = lines[0].removeprefix("# Incident investigation: ").strip() if lines else ""
            service_line = next((line for line in lines if line.startswith("- Service:")), "")
            summary_line = next((line for line in lines if line.startswith("- Summary:")), "")
            action = _report_code_value(lines, "- Action:")
            command = _report_code_value(lines, "- Command:")
            reasoning_line = next((line for line in lines if line.startswith("- Reasoning:")), "")
            risk_line = next((line for line in lines if line.startswith("- Risk:")), "")
            risk = risk_line.split("**")[1] if "**" in risk_line else ""
            remediation = None
            if action in {"restart", "scale", "rollback", "none"} and risk in {
                "low",
                "medium",
                "high",
            }:
                remediation = {
                    "action": action,
                    "command": "" if command == "None suggested." else command,
                    "reasoning": reasoning_line.removeprefix("- Reasoning:").strip(),
                    "risk": risk,
                    "requires_human_approval": True,
                }
            summaries[report_path.stem] = {
                "incident_id": report_path.stem,
                "alert_name": title or "Saved incident report",
                "service": service_line.split("`")[1] if "`" in service_line else "unknown",
                "summary": summary_line.removeprefix("- Summary:").strip(),
                "received_at": datetime.fromtimestamp(report_path.stat().st_mtime, UTC).isoformat(),
                "status": "saved_report",
                "hypotheses": [],
                "remediation": remediation,
                "agent_statuses": [],
            }

    return {
        "incidents": sorted(
            summaries.values(),
            key=lambda item: str(item["received_at"]),
            reverse=True,
        )
    }


@app.get("/api/incidents/{fingerprint}/events")
async def get_incident_events(
    fingerprint: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, object]:
    path = Path(os.getenv("AGENT_LOG_PATH", "artifacts/agent-events.jsonl"))
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No structured agent log is available.")

    events: deque[dict[str, object]] = deque(maxlen=limit)
    matched = 0
    with path.open(encoding="utf-8") as log_file:
        for line in log_file:
            event = json.loads(line)
            input_data = event.get("input")
            alert = input_data.get("alert") if isinstance(input_data, dict) else None
            if isinstance(alert, dict) and alert.get("incident_id") == fingerprint:
                events.append(event)
                matched += 1
    if not matched:
        raise HTTPException(status_code=404, detail="No agent events found for this incident.")
    return {
        "incident_id": fingerprint,
        "events": list(events),
        "truncated": matched > limit,
        "total_events": matched,
    }


@app.post("/alerts")
async def receive_alerts(payload: AlertmanagerPayload) -> dict[str, object]:
    results: list[dict[str, object]] = []
    for alert_model in payload.alerts:
        alert = alert_model.model_dump()
        alert["alertname"] = alert_model.labels.get(
            "alertname", payload.commonLabels.get("alertname", "Unknown alert")
        )
        alert["service"] = alert_model.labels.get(
            "service", payload.commonLabels.get("service", "")
        )
        fingerprint = _incident_fingerprint(alert_model.fingerprint, alert)
        if payload.status == "resolved" or alert_model.status == "resolved":
            incident = incidents.get(fingerprint)
            if incident is None:
                results.append(
                    {
                        "fingerprint": fingerprint,
                        "status": "resolved_without_analysis",
                    }
                )
                continue
            path = _make_postmortem(
                fingerprint,
                incident,
                "Alertmanager reported the alert as resolved.",
                ["Verify recovery against the SLO window and add follow-up actions."],
                alert_model.endsAt or datetime.now(UTC).isoformat(),
            )
            results.append(
                {
                    "fingerprint": fingerprint,
                    "status": "postmortem_generated",
                    "path": str(path),
                }
            )
            continue

        alert_context = _alert_context(alert, fingerprint, alert_model.annotations)
        outputs, rca, remediation, report = await orchestrator.investigate(alert_context)
        report_path = write_incident_report(
            report,
            fingerprint,
            Path(os.getenv("INCIDENT_REPORT_DIR", "artifacts/incidents")),
        )
        evidence = _legacy_evidence(outputs)
        hypotheses = rca.hypotheses
        incident = IncidentRecord(
            alert=alert,
            evidence=evidence,
            hypotheses=hypotheses,
            received_at=datetime.now(UTC).isoformat(),
            agent_outputs=outputs,
            rca=rca,
            remediation=remediation,
            report_path=report_path,
        )
        incidents[fingerprint] = incident
        results.append(
            {
                "fingerprint": fingerprint,
                "status": "analyzed",
                "alert": alert,
                "evidence": [item.model_dump() for item in incident.evidence],
                "hypotheses": [item.model_dump() for item in incident.hypotheses],
                "agents": [item.model_dump(mode="json") for item in incident.agent_outputs],
                "remediation": incident.remediation.model_dump(),
                "report_path": str(report_path),
            }
        )
    return {"status": "processed", "results": results}


@app.get("/incidents/{fingerprint}/report", response_class=PlainTextResponse)
async def show_incident_report(fingerprint: str) -> PlainTextResponse:
    incident = incidents.get(fingerprint)
    report_path = (
        incident.report_path
        if incident is not None
        else incident_report_path(
            fingerprint, Path(os.getenv("INCIDENT_REPORT_DIR", "artifacts/incidents"))
        )
    )
    if not report_path.is_file():
        raise HTTPException(status_code=404, detail="No analyzed incident has this ID.")
    return PlainTextResponse(report_path.read_text(encoding="utf-8"))


@app.post("/incidents/{fingerprint}/resolve")
async def resolve_incident(fingerprint: str, request: ResolutionRequest) -> dict[str, str]:
    incident = incidents.get(fingerprint)
    if incident is None:
        raise HTTPException(status_code=404, detail="No analyzed incident has this fingerprint.")
    path = _make_postmortem(fingerprint, incident, request.summary, request.corrective_actions)
    return {"status": "postmortem_generated", "path": str(path)}


@app.post("/approvals/{action}")
async def approve_runbook(
    action: Literal["restart", "scale", "rollback"],
    request: ApprovalRequest,
    x_approval_token: str | None = Header(default=None),
) -> dict[str, object]:
    _audit(action, request.service, request.approver, "requested")
    if not request.approved:
        _audit(action, request.service, request.approver, "rejected", {"reason": "not approved"})
        raise HTTPException(status_code=400, detail="Explicit approval is required.")

    configured_token = os.getenv("APPROVAL_TOKEN", "")
    if not configured_token:
        _audit(
            action,
            request.service,
            request.approver,
            "rejected",
            {"reason": "approval token is not configured"},
        )
        raise HTTPException(
            status_code=503, detail="Runbook API is disabled until APPROVAL_TOKEN is configured."
        )
    if not x_approval_token or not hmac.compare_digest(x_approval_token, configured_token):
        _audit(
            action,
            request.service,
            request.approver,
            "rejected",
            {"reason": "invalid approval token"},
        )
        raise HTTPException(status_code=401, detail="A valid X-Approval-Token is required.")
    if action == "scale" and request.replicas is None:
        _audit(
            action,
            request.service,
            request.approver,
            "rejected",
            {"reason": "replica count is required"},
        )
        raise HTTPException(status_code=422, detail="Scaling requires replicas between 2 and 10.")
    if action != "scale" and request.replicas is not None:
        _audit(
            action,
            request.service,
            request.approver,
            "rejected",
            {"reason": "replicas only apply to scale"},
        )
        raise HTTPException(status_code=422, detail="The replicas field only applies to scale.")

    try:
        outcome = await run_in_threadpool(
            kubernetes.perform_action, action, request.service, request.replicas
        )
    except (ApiException, RuntimeError, ValueError) as error:
        _audit(action, request.service, request.approver, "failed", {"reason": str(error)})
        raise HTTPException(status_code=502, detail=f"Runbook action failed: {error}") from error
    _audit(action, request.service, request.approver, "succeeded", outcome)
    return {"status": "action_completed", **outcome}
