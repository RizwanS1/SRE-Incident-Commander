from __future__ import annotations

import json
import os
from typing import Protocol

import requests
from pydantic import ValidationError

from incident_commander.models import Evidence, Hypothesis


class HypothesisProvider(Protocol):
    def rank(self, alert: dict[str, object], evidence: list[Evidence]) -> list[Hypothesis]: ...


class MockHypothesisProvider:
    def rank(self, alert: dict[str, object], evidence: list[Evidence]) -> list[Hypothesis]:
        ranked: list[Hypothesis] = []
        for item in evidence:
            statement = item.statement.lower()
            if item.source == "prometheus" and item.value is not None:
                if "error ratio" in statement and item.value >= 0.005:
                    ranked.append(
                        Hypothesis(
                            title="Elevated service error rate is contributing to the alert",
                            explanation=(
                                f"The measured error ratio is {item.value:.4f}; confirm the "
                                "affected request path and dependency before remediation."
                            ),
                            confidence=0.8,
                            evidence_ids=[item.evidence_id],
                        )
                    )
                elif "availability" in statement and item.value < 0.995:
                    ranked.append(
                        Hypothesis(
                            title="Observed availability is below the 99.5% target",
                            explanation=(
                                f"Prometheus reports availability {item.value:.4f} for the "
                                "five-minute recording window."
                            ),
                            confidence=0.75,
                            evidence_ids=[item.evidence_id],
                        )
                    )
            if item.source in {"pod_log", "event"} and any(
                marker in statement for marker in ("error", "exception", "oomkilled", "chaos")
            ):
                ranked.append(
                    Hypothesis(
                        title="A recent pod log or event records an explicit failure signal",
                        explanation=(
                            "The cited Kubernetes evidence contains a failure-related message; "
                            "verify whether it matches the alert time and affected workload."
                        ),
                        confidence=0.65,
                        evidence_ids=[item.evidence_id],
                    )
                )
            if item.source == "trace" and item.value is not None:
                status = str(item.statement).lower()
                if "status=error" in status:
                    ranked.append(
                        Hypothesis(
                            title="A failing span was observed in the request trace",
                            explanation=(
                                "The trace contains a span marked as failed; inspect the "
                                "cited span and its parent/child context."
                            ),
                            confidence=0.75,
                            evidence_ids=[item.evidence_id],
                        )
                    )
                elif item.value >= 500:
                    ranked.append(
                        Hypothesis(
                            title="A slow span was observed in the request trace",
                            explanation=(
                                f"The cited span duration is {item.value:.1f}ms; compare it "
                                "with the service's latency objective."
                            ),
                            confidence=0.6,
                            evidence_ids=[item.evidence_id],
                        )
                    )
            if item.source == "deployment" and "recent rollout" in statement:
                ranked.append(
                    Hypothesis(
                        title="A recent deployment may be related to the incident",
                        explanation=(
                            "A recent ReplicaSet revision was observed. Temporal correlation "
                            "does not establish that the rollout caused the alert."
                        ),
                        confidence=0.5,
                        evidence_ids=[item.evidence_id],
                    )
                )

        if not ranked:
            cited = evidence[0].evidence_id if evidence else ""
            if cited:
                ranked.append(
                    Hypothesis(
                        title="Insufficient telemetry to identify a root cause",
                        explanation=(
                            "The collected evidence does not establish a specific cause; "
                            "inspect the cited data and collect more signals."
                        ),
                        confidence=0.1,
                        evidence_ids=[cited],
                    )
                )
        return ranked


class OpenAICompatibleHypothesisProvider:
    def __init__(self) -> None:
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.api_key = os.getenv("LLM_API_KEY", "")

    def rank(self, alert: dict[str, object], evidence: list[Evidence]) -> list[Hypothesis]:
        if not self.api_key:
            raise RuntimeError("LLM_API_KEY is required when LLM_PROVIDER=openai.")
        prompt = {
            "alert": alert,
            "evidence": [item.model_dump() for item in evidence],
            "required_output": [
                {
                    "title": "concise hypothesis",
                    "explanation": "what evidence supports it and what remains uncertain",
                    "confidence": "number between 0 and 1",
                    "evidence_ids": ["one or more exact evidence_id values"],
                }
            ],
        }
        messages = [
            {
                "role": "system",
                "content": (
                    "You are the RCA Agent. Use only supplied telemetry and distinguish "
                    "correlation from causation. Return only one JSON object with exactly "
                    '{"hypotheses":[{"title":"short hypothesis",'
                    '"explanation":"evidence-based reasoning and uncertainty",'
                    '"confidence":0.5,"evidence_ids":["exact evidence_id"]}]}. Every '
                    "hypothesis must cite exact evidence_id values from the input. Do "
                    "not invent telemetry or use fields named id or description. If the "
                    "evidence does not support a root cause, return an empty hypotheses array."
                ),
            },
            {"role": "user", "content": json.dumps(prompt)},
        ]
        for attempt in range(2):
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                    "messages": messages,
                },
                timeout=30,
            )
            response.raise_for_status()
            body = response.json()
            content = body["choices"][0]["message"]["content"]
            try:
                parsed = json.loads(content)
                if not isinstance(parsed, dict) or not isinstance(parsed.get("hypotheses"), list):
                    raise ValueError("Response must contain a 'hypotheses' list.")
                return [Hypothesis.model_validate(item) for item in parsed["hypotheses"]]
            except (TypeError, ValueError, ValidationError) as error:
                if attempt:
                    raise ValueError(
                        "LLM response failed the required hypotheses schema "
                        "after one correction attempt."
                    ) from error
                messages.extend(
                    [
                        {"role": "assistant", "content": content},
                        {
                            "role": "user",
                            "content": (
                                "The previous response did not match the required schema. "
                                'Return only {"hypotheses":[{"title":"short hypothesis",'
                                '"explanation":"evidence-based reasoning and uncertainty",'
                                '"confidence":0.5,"evidence_ids":["exact evidence_id"]}]}. '
                                "Use exact evidence_id values from the original input, or "
                                'return {"hypotheses":[]} if none are supported.'
                            ),
                        },
                    ]
                )
        raise RuntimeError("LLM response retry loop ended unexpectedly.")


def create_provider() -> HypothesisProvider:
    provider = os.getenv("LLM_PROVIDER", "mock").lower()
    if provider == "mock":
        return MockHypothesisProvider()
    if provider == "openai":
        return OpenAICompatibleHypothesisProvider()
    raise ValueError("LLM_PROVIDER must be 'mock' or 'openai'.")
