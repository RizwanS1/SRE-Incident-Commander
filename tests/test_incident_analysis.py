from incident_commander.agents.schemas import (
    AgentOutput,
    EvidenceRecord,
    RcaOutput,
    RemediationSuggestion,
)
from incident_commander.analysis import IncidentAnalyzer, validate_hypotheses
from incident_commander.collectors import redact_sensitive
from incident_commander.llm import MockHypothesisProvider
from incident_commander.models import Evidence, Hypothesis


class FakePrometheus:
    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        return [
            Evidence(
                evidence_id="error-ratio",
                source="prometheus",
                observed_at="2026-01-01T00:00:00Z",
                statement="Five-minute error ratio for orders is 0.020000.",
                value=0.02,
            )
        ]


class FakeKubernetes:
    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        return [
            Evidence(
                evidence_id="rollout",
                source="deployment",
                observed_at="2026-01-01T00:00:00Z",
                statement="Recent rollout for orders: ReplicaSet orders-new, revision=2.",
            )
        ]


def test_analyzer_ranks_only_hypotheses_with_real_citations() -> None:
    analyzer = IncidentAnalyzer(FakePrometheus(), FakeKubernetes(), MockHypothesisProvider())

    evidence, hypotheses = analyzer.analyze({"service": "orders"})

    assert {item.evidence_id for item in evidence} == {"error-ratio", "rollout"}
    assert hypotheses
    assert all(
        set(hypothesis.evidence_ids) <= {item.evidence_id for item in evidence}
        for hypothesis in hypotheses
    )
    assert hypotheses[0].confidence >= hypotheses[-1].confidence


def test_validator_drops_unknown_or_uncorroborated_citations() -> None:
    evidence = [
        Evidence(
            evidence_id="availability",
            source="prometheus",
            observed_at="now",
            statement="Five-minute availability is 0.980000.",
            value=0.98,
        )
    ]
    unsupported_rollout = Hypothesis(
        title="A recent deployment caused the outage",
        explanation="A rollout is the root cause.",
        confidence=0.95,
        evidence_ids=["availability"],
    )
    hallucinated_reference = Hypothesis(
        title="The database is down",
        explanation="Database failure caused the incident.",
        confidence=0.9,
        evidence_ids=["made-up-evidence"],
    )

    assert validate_hypotheses([unsupported_rollout, hallucinated_reference], evidence) == []


def test_validator_orders_and_deduplicates_supported_hypotheses() -> None:
    evidence = [
        Evidence(
            evidence_id="error-ratio",
            source="prometheus",
            observed_at="now",
            statement="Five-minute error ratio is 0.020000.",
            value=0.02,
        )
    ]
    likely = Hypothesis(
        title="Elevated error rate",
        explanation="The error ratio is elevated.",
        confidence=0.9,
        evidence_ids=["error-ratio"],
    )
    possible = Hypothesis(
        title="Possible elevated error ratio",
        explanation="The error ratio is elevated.",
        confidence=0.5,
        evidence_ids=["error-ratio"],
    )

    validated = validate_hypotheses([possible, likely, likely], evidence)

    assert validated == [likely, possible]


def test_validator_rejects_a_claim_contradicted_by_the_metric_value() -> None:
    evidence = [
        Evidence(
            evidence_id="p95-latency",
            source="prometheus",
            observed_at="now",
            statement="Five-minute p95 latency is 0.100000 seconds.",
            value=0.1,
        )
    ]
    hypothesis = Hypothesis(
        title="High latency is the root cause",
        explanation="The cited p95 value shows a slow response.",
        confidence=0.99,
        evidence_ids=["p95-latency"],
    )

    assert validate_hypotheses([hypothesis], evidence) == []


def test_log_redaction_removes_common_credentials() -> None:
    sanitized = redact_sensitive(
        "authorization: Bearer header-secret password=hunter2 api_key=key-value"
    )

    assert "header-secret" not in sanitized
    assert "hunter2" not in sanitized
    assert "key-value" not in sanitized


def test_alert_metadata_is_redacted_and_reduced_before_provider_use() -> None:
    captured_alert: dict[str, object] = {}

    class CaptureProvider:
        def rank(self, alert: dict[str, object], evidence: list[Evidence]) -> list[Hypothesis]:
            captured_alert.update(alert)
            return []

    analyzer = IncidentAnalyzer(FakePrometheus(), FakeKubernetes(), CaptureProvider())
    analyzer.analyze(
        {
            "alertname": "Incident",
            "service": "orders",
            "startsAt": "2026-01-01T00:00:00Z",
            "annotations": {"summary": "token=do-not-send"},
            "extra_label": "do-not-forward",
        }
    )

    assert "do-not-send" not in str(captured_alert)
    assert "do-not-forward" not in str(captured_alert)
    assert captured_alert["summary"] == "token=[REDACTED]"


def test_resolved_alert_creates_postmortem_from_validated_analysis(monkeypatch, tmp_path) -> None:
    from fastapi.testclient import TestClient

    import incident_commander.app as incident_app

    class FakeOrchestrator:
        async def investigate(self, alert):
            evidence = [
                EvidenceRecord(
                    evidence_id="availability",
                    agent="metrics",
                    source="prometheus",
                    observed_at="2026-01-01T00:00:00Z",
                    statement="Five-minute availability for orders is 0.980000.",
                    raw_value=0.98,
                    labels={"service": "orders", "metric": "availability"},
                )
            ]
            hypothesis = Hypothesis(
                title="Observed availability is below the 99.5% target",
                explanation="Prometheus reports availability 0.9800.",
                confidence=0.75,
                evidence_ids=["availability"],
            )
            output = AgentOutput(
                agent="metrics",
                status="complete",
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                evidence=evidence,
                findings=["Prometheus fixture replayed."],
            )
            rca = RcaOutput(hypotheses=[hypothesis], evidence_ids=["availability"])
            remediation = RemediationSuggestion(
                action="none",
                command="",
                reasoning="No action in test.",
                risk="low",
            )
            return [output], rca, remediation, "# Incident investigation"

    monkeypatch.setenv("KUBERNETES_ENABLED", "false")
    monkeypatch.setenv("POSTMORTEM_DIR", str(tmp_path))
    monkeypatch.setenv("INCIDENT_REPORT_DIR", str(tmp_path / "incidents"))
    monkeypatch.setattr(incident_app, "orchestrator", FakeOrchestrator())
    incident_app.incidents.clear()
    alert = {
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "Availability", "service": "orders"},
                "annotations": {},
                "startsAt": "2026-01-01T00:00:00Z",
                "fingerprint": "incident-test",
            }
        ],
    }

    with TestClient(incident_app.app) as client:
        analysis = client.post("/alerts", json=alert)
        alert["status"] = "resolved"
        alert["alerts"][0]["status"] = "resolved"
        resolution = client.post("/alerts", json=alert)

    assert analysis.status_code == 200
    assert analysis.json()["results"][0]["hypotheses"][0]["evidence_ids"] == ["availability"]
    assert analysis.json()["results"][0]["report_path"].endswith("incident-test.md")
    assert resolution.status_code == 200
    result = resolution.json()["results"][0]
    assert result["status"] == "postmortem_generated"
    postmortem = tmp_path / "incident-test.md"
    assert postmortem.is_file()
    report = postmortem.read_text(encoding="utf-8")
    assert "Availability SLO: 99.5%" in report
    assert "shortfall 1.50%" in report
    assert "Alert received:" in report
    assert "## Root cause" in report
    with TestClient(incident_app.app) as client:
        investigation = client.get("/incidents/incident-test/report")
    incident_app.incidents.clear()
    with TestClient(incident_app.app) as client:
        persisted_investigation = client.get("/incidents/incident-test/report")
    assert investigation.status_code == 200
    assert investigation.text == "# Incident investigation"
    assert persisted_investigation.status_code == 200


def test_runbook_requires_token_and_writes_audit_records(monkeypatch, tmp_path) -> None:
    from fastapi.testclient import TestClient

    import incident_commander.app as incident_app

    monkeypatch.setenv("KUBERNETES_ENABLED", "false")
    monkeypatch.setenv("APPROVAL_TOKEN", "test-token")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    calls: list[tuple[str, str, int | None]] = []

    def perform_action(action: str, service: str, replicas: int | None = None) -> dict[str, object]:
        calls.append((action, service, replicas))
        return {"action": action, "service": service, "replicas": replicas}

    monkeypatch.setattr(incident_app.kubernetes, "perform_action", perform_action)
    body = {
        "approved": True,
        "approver": "Operator",
        "service": "orders",
        "replicas": 2,
    }

    with TestClient(incident_app.app) as client:
        rejected = client.post("/approvals/scale", json=body)
        accepted = client.post(
            "/approvals/scale",
            json=body,
            headers={"X-Approval-Token": "test-token"},
        )

    assert rejected.status_code == 401
    assert accepted.status_code == 200
    assert calls == [("scale", "orders", 2)]
    audit_lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert '"outcome": "rejected"' in audit_lines[1]
    assert '"outcome": "succeeded"' in audit_lines[-1]
