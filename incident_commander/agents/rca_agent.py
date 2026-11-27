from __future__ import annotations

from incident_commander.agents.schemas import (
    AgentOutput,
    EvidenceRecord,
    MetricsOutput,
    RcaInput,
    RcaOutput,
    TraceOutput,
)
from incident_commander.analysis import validate_hypotheses
from incident_commander.llm import HypothesisProvider
from incident_commander.models import Evidence


class RcaAgent:
    def __init__(self, provider: HypothesisProvider) -> None:
        self.provider = provider

    def run(self, request: RcaInput) -> RcaOutput:
        records = self._select_evidence(request.agent_outputs)
        legacy_evidence = [
            Evidence(
                evidence_id=item.evidence_id,
                source=self._legacy_source(item),
                observed_at=item.observed_at.isoformat(),
                statement=item.statement,
                value=item.raw_value if isinstance(item.raw_value, float) else None,
            )
            for item in records
        ]
        alert = {
            "alertname": request.alert.alert_name,
            "service": request.alert.service,
            "startsAt": request.alert.starts_at.isoformat(),
            "annotations": {
                "summary": request.alert.summary,
                "description": request.alert.description,
            },
            "agent_findings": [
                {
                    "agent": output.agent,
                    "findings": output.findings,
                    "warnings": output.warnings,
                }
                for output in request.agent_outputs
            ],
        }
        hypotheses = validate_hypotheses(
            self.provider.rank(alert, legacy_evidence), legacy_evidence
        )
        cited_ids = list(
            dict.fromkeys(
                evidence_id for hypothesis in hypotheses for evidence_id in hypothesis.evidence_ids
            )
        )
        return RcaOutput(
            hypotheses=hypotheses,
            evidence_ids=cited_ids,
            warnings=[warning for output in request.agent_outputs for warning in output.warnings],
        )

    @staticmethod
    def _select_evidence(outputs: list[AgentOutput]) -> list[EvidenceRecord]:
        selected: list[EvidenceRecord] = []
        for output in outputs:
            if isinstance(output, MetricsOutput):
                groups: dict[tuple[str, str], list[EvidenceRecord]] = {}
                for item in output.evidence:
                    key = (item.labels.get("service", ""), item.labels.get("metric", ""))
                    groups.setdefault(key, []).append(item)
                for (_, metric), items in groups.items():
                    latest = max(items, key=lambda item: item.observed_at)
                    if metric == "availability":
                        extreme = min(items, key=lambda item: float(item.raw_value or 0))
                    else:
                        extreme = max(items, key=lambda item: float(item.raw_value or 0))
                    selected.extend({item.evidence_id: item for item in (latest, extreme)}.values())
            elif isinstance(output, TraceOutput):
                span_ids = {output.slowest_span_id, output.failing_span_id} - {None}
                selected.extend(
                    item for item in output.evidence if item.labels.get("span_id") in span_ids
                )
            else:
                selected.extend(output.evidence)
        return selected

    @staticmethod
    def _legacy_source(item: EvidenceRecord) -> str:
        if item.agent == "metrics":
            return "prometheus"
        if item.agent == "changes":
            return "deployment" if item.source == "deployment" else item.source
        if item.agent == "logs":
            return item.source
        if item.agent == "traces":
            return "trace"
        return "system"
