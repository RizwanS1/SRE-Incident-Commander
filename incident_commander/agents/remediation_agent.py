from __future__ import annotations

from incident_commander.agents.schemas import RemediationInput, RemediationSuggestion


class RemediationAgent:
    """Suggests a command for a human; this module never shells out or calls Kubernetes."""

    def run(self, request: RemediationInput) -> RemediationSuggestion:
        supported_evidence = {item.evidence_id for item in request.evidence}
        supported_hypotheses = [
            item
            for item in request.hypotheses
            if item.evidence_ids and set(item.evidence_ids) <= supported_evidence
        ]
        if not supported_hypotheses:
            return RemediationSuggestion(
                action="none",
                command="",
                reasoning="No validated, evidence-cited hypothesis supports a safe action.",
                risk="low",
            )
        leading_hypothesis = supported_hypotheses[0]
        cited_ids = set(leading_hypothesis.evidence_ids)
        cited_evidence = [item for item in request.evidence if item.evidence_id in cited_ids]
        evidence_text = " ".join(item.statement for item in cited_evidence).lower()
        if any(marker in evidence_text for marker in ("recent rollout", "recent deployment")):
            return RemediationSuggestion(
                action="rollback",
                command=f"kubectl rollout undo deployment/{request.alert.service} -n sre",
                reasoning=(
                    "A recent rollout is correlated with the alert. Verify the target revision "
                    "and impact before running this command."
                ),
                risk="high",
            )
        if any(
            marker in evidence_text for marker in ("oomkilled", "outofmemory", "out of memory")
        ) or any(
            item.labels.get("metric") in {"memory_limit_utilization", "cpu_limit_utilization"}
            and isinstance(item.raw_value, float)
            and item.raw_value >= 0.9
            for item in cited_evidence
        ):
            return RemediationSuggestion(
                action="scale",
                command=f"kubectl scale deployment/{request.alert.service} --replicas=2 -n sre",
                reasoning=(
                    "A memory pressure or OOM signal was observed. Confirm cluster capacity, "
                    "resource limits, and replica safety before scaling."
                ),
                risk="medium",
            )
        has_process_failure = any(
            item.source in {"pod_log", "event"}
            and any(
                marker in item.statement.lower()
                for marker in (
                    "crashloopbackoff",
                    "fatal error",
                    "panic:",
                    "process exited",
                    "segmentation fault",
                    "uncaught exception",
                )
            )
            for item in cited_evidence
        )
        if not has_process_failure:
            return RemediationSuggestion(
                action="none",
                command="",
                reasoning=(
                    "The evidence confirms impact but does not identify a recent rollout, "
                    "resource saturation, or process-level failure. A restart is not "
                    "supported; inspect the agent evidence before choosing a corrective action."
                ),
                risk="low",
            )
        return RemediationSuggestion(
            action="restart",
            command=f"kubectl rollout restart deployment/{request.alert.service} -n sre",
            reasoning=(
                "A validated service error signal was observed. A restart is disruptive; "
                "check current rollout health and obtain operator approval first."
            ),
            risk="medium",
        )
