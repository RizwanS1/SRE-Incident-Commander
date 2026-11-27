from __future__ import annotations

import re
from pathlib import Path

from incident_commander.agents.schemas import (
    AgentOutput,
    AlertContext,
    RcaOutput,
    RemediationSuggestion,
)


def render_incident_report(
    alert: AlertContext,
    outputs: list[AgentOutput],
    rca: RcaOutput,
    remediation: RemediationSuggestion,
) -> str:
    evidence_by_id = {
        evidence.evidence_id: evidence
        for agent_output in outputs
        for evidence in agent_output.evidence
    }
    lines = [
        f"# Incident investigation: {alert.alert_name}",
        "",
        f"- Incident ID: `{alert.incident_id}`",
        f"- Service: `{alert.service}`",
        f"- Alert started: {alert.starts_at.isoformat()}",
        f"- Summary: {alert.summary or 'Not provided.'}",
        "",
        "## Timeline",
        f"- Alert started: {alert.starts_at.isoformat()}",
        *[
            f"- {output.agent} investigation: {output.started_at.isoformat()} to "
            f"{output.completed_at.isoformat()} ({output.status})"
            for output in outputs
        ],
        "",
        "## Per-agent findings",
    ]
    for output in outputs:
        lines.extend(["", f"### {output.agent.title()} ({output.status})"])
        lines.extend(f"- {finding}" for finding in output.findings)
        lines.extend(f"- Warning: {warning}" for warning in output.warnings)
        if output.evidence:
            lines.extend(
                f"- `{item.evidence_id}` ({item.source}, {item.observed_at.isoformat()}): "
                f"{item.statement}"
                for item in output.evidence
            )
        else:
            lines.append("- No validated telemetry was returned.")
    lines.extend(["", "## RCA hypothesis"])
    if rca.hypotheses:
        for index, hypothesis in enumerate(rca.hypotheses, 1):
            cited = ", ".join(f"`{item}`" for item in hypothesis.evidence_ids)
            lines.append(
                f"{index}. **{hypothesis.title}** (confidence {hypothesis.confidence:.0%}) — "
                f"{hypothesis.explanation} Evidence: {cited}."
            )
            for evidence_id in hypothesis.evidence_ids:
                evidence = evidence_by_id[evidence_id]
                lines.append(f"   - `{evidence_id}` ({evidence.agent}): {evidence.statement}")
    else:
        lines.append("No hypothesis passed evidence validation; investigate manually.")
    lines.extend(
        [
            "",
            "## Suggested manual remediation",
            f"- Action: `{remediation.action}`",
            f"- Command: `{remediation.command or 'None suggested.'}`",
            f"- Reasoning: {remediation.reasoning}",
            f"- Risk: **{remediation.risk}**",
            "- Requires explicit human approval; this report did not execute the command.",
            "",
            "## SLO impact",
            "- Availability objective: 99.5%.",
        ]
    )
    metric_evidence = [
        item
        for item in evidence_by_id.values()
        if item.agent == "metrics"
        and item.labels.get("metric") in {"error_ratio", "p95_latency_seconds"}
    ]
    if metric_evidence:
        lines.extend(
            f"- {item.statement} (evidence `{item.evidence_id}`)" for item in metric_evidence
        )
    else:
        lines.append("- No validated Prometheus SLI samples were available for this incident.")
    lines.append("")
    return "\n".join(lines)


def write_incident_report(report: str, incident_id: str, output_dir: Path) -> Path:
    path = incident_report_path(incident_id, output_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")
    return path


def incident_report_path(incident_id: str, output_dir: Path) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "-", incident_id).strip("-")
    if not safe_id:
        raise ValueError("Incident ID must contain at least one safe filename character.")
    return output_dir / f"{safe_id}.md"
