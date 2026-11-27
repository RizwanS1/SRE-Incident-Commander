from __future__ import annotations

import re
from pathlib import Path

from incident_commander.models import Evidence, Hypothesis


def generate_postmortem(
    fingerprint: str,
    alert: dict[str, object],
    received_at: str,
    resolved_at: str,
    evidence: list[Evidence],
    hypotheses: list[Hypothesis],
    resolution_summary: str,
    corrective_actions: list[str],
    output_dir: Path,
) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "-", fingerprint).strip("-") or "incident"
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{safe_id}.md"
    alert_name = str(alert.get("alertname", "Unknown alert"))
    service = str(alert.get("service", "unknown"))
    start = str(alert.get("startsAt", "unknown"))
    lines = [
        f"# Incident postmortem: {alert_name}",
        "",
        f"- Incident fingerprint: `{safe_id}`",
        f"- Affected service: `{service}`",
        "",
        "## Timeline",
        f"- Alert started: {start}",
        f"- Alert received: {received_at}",
        f"- Resolved: {resolved_at}",
        "",
        "## Impact vs SLO",
        "- Availability SLO: 99.5%.",
    ]
    for item in evidence:
        if item.source == "prometheus" and item.value is not None:
            lines.append(f"- {item.statement} (evidence `{item.evidence_id}`)")
            if item.labels.get("metric") == "availability":
                shortfall = max(0.995 - item.value, 0)
                lines.append(
                    f"- Availability sample {item.value:.2%} vs 99.50% target "
                    f"(shortfall {shortfall:.2%}; evidence `{item.evidence_id}`)."
                )
    if not any(item.source == "prometheus" and item.value is not None for item in evidence):
        lines.append("- No numeric Prometheus sample was available; impact is not quantified.")
    lines.extend(
        [
            "",
            "## Root cause",
            "**Status:** unverified hypotheses; confirm before publishing a causal conclusion.",
            "",
        ]
    )
    if hypotheses:
        for rank, hypothesis in enumerate(hypotheses, start=1):
            cited = ", ".join(f"`{item}`" for item in hypothesis.evidence_ids)
            lines.append(
                f"{rank}. **{hypothesis.title}** (confidence {hypothesis.confidence:.0%}) — "
                f"{hypothesis.explanation} Evidence: {cited}."
            )
    else:
        lines.append("No hypothesis passed evidence validation.")
    lines.extend(["", "## Resolution", resolution_summary, "", "## Corrective actions"])
    if corrective_actions:
        lines.extend(f"- {action}" for action in corrective_actions)
    else:
        lines.append("- Follow up with corrective actions based on the verified root cause.")
    lines.extend(
        [
            "",
            "> This report uses telemetry snapshots and ranked hypotheses; it does not assert "
            "causation unless independently confirmed.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
