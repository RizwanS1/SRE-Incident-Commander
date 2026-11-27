from __future__ import annotations

from typing import Protocol

from incident_commander.collectors import redact_sensitive
from incident_commander.llm import HypothesisProvider
from incident_commander.models import Evidence, Hypothesis


class EvidenceCollector(Protocol):
    def collect(self, alert: dict[str, object]) -> list[Evidence]: ...


def validate_hypotheses(hypotheses: list[Hypothesis], evidence: list[Evidence]) -> list[Hypothesis]:
    evidence_by_id = {item.evidence_id: item for item in evidence}
    validated: list[Hypothesis] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for hypothesis in hypotheses:
        citations = list(dict.fromkeys(hypothesis.evidence_ids))
        if not citations or any(citation not in evidence_by_id for citation in citations):
            continue
        cited_evidence = [evidence_by_id[citation] for citation in citations]
        claim = f"{hypothesis.title} {hypothesis.explanation}".lower()
        if any(term in claim for term in ("rollout", "deployment", "release")) and not any(
            item.source == "deployment" and "recent rollout" in item.statement.lower()
            for item in cited_evidence
        ):
            continue
        if any(term in claim for term in ("latency", "slow response")) and not any(
            item.source == "prometheus"
            and "latency" in item.statement.lower()
            and (
                not any(word in claim for word in ("high", "elevated", "slow", "exceeds"))
                or item.value is not None
                and item.value >= 0.5
            )
            for item in cited_evidence
        ):
            continue
        if any(term in claim for term in ("error rate", "5xx", "error ratio")) and not any(
            item.source == "prometheus"
            and "error ratio" in item.statement.lower()
            and item.value is not None
            and item.value >= 0.005
            for item in cited_evidence
        ):
            continue
        if any(
            term in claim for term in ("availability below", "below the 99.5%", "below target")
        ) and not any(
            item.source == "prometheus"
            and "availability" in item.statement.lower()
            and item.value is not None
            and item.value < 0.995
            for item in cited_evidence
        ):
            continue
        if any(term in claim for term in ("memory", "oom", "out of memory")) and not any(
            item.source in {"pod", "pod_log", "event"}
            and any(marker in item.statement.lower() for marker in ("memory", "oom", "killed"))
            for item in cited_evidence
        ):
            continue
        if "database" in claim and not any(
            "database" in item.statement.lower() for item in cited_evidence
        ):
            continue
        if any(term in claim for term in ("trace", "span")) and not any(
            item.source == "trace" for item in cited_evidence
        ):
            continue
        if any(
            term in claim for term in ("failing span", "failed span", "span failed")
        ) and not any(
            item.source == "trace" and "status=error" in item.statement.lower()
            for item in cited_evidence
        ):
            continue
        if any(term in claim for term in ("slow span", "slowest span")) and not any(
            item.source == "trace" and item.value is not None and item.value >= 500
            for item in cited_evidence
        ):
            continue
        identity = (hypothesis.title.casefold(), tuple(sorted(citations)))
        if identity in seen:
            continue
        seen.add(identity)
        validated.append(hypothesis.model_copy(update={"evidence_ids": citations}))
    return sorted(validated, key=lambda item: item.confidence, reverse=True)


class IncidentAnalyzer:
    def __init__(
        self,
        prometheus: EvidenceCollector,
        kubernetes: EvidenceCollector,
        provider: HypothesisProvider,
    ) -> None:
        self.prometheus = prometheus
        self.kubernetes = kubernetes
        self.provider = provider

    def analyze(self, alert: dict[str, object]) -> tuple[list[Evidence], list[Hypothesis]]:
        evidence = self.prometheus.collect(alert)
        evidence.extend(self.kubernetes.collect(alert))
        annotations = alert.get("annotations")
        annotation_values = annotations if isinstance(annotations, dict) else {}
        provider_alert = {
            key: redact_sensitive(str(value))
            for key, value in {
                "alertname": alert.get("alertname", "Unknown alert"),
                "service": alert.get("service", ""),
                "startsAt": alert.get("startsAt", ""),
                "summary": annotation_values.get("summary", ""),
                "description": annotation_values.get("description", ""),
            }.items()
        }
        hypotheses = self.provider.rank(provider_alert, evidence)
        return evidence, validate_hypotheses(hypotheses, evidence)
