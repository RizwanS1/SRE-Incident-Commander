import json
from pathlib import Path

from fastapi.testclient import TestClient

import incident_commander.app as incident_app


def test_dashboard_and_static_assets_are_served() -> None:
    with TestClient(incident_app.app) as client:
        page = client.get("/")
        script = client.get("/static/app.js")

    assert page.status_code == 200
    assert "Incident Commander" in page.text
    assert script.status_code == 200
    assert "refreshDashboard" in script.text


def test_observability_shortcuts_stay_with_selected_incident() -> None:
    with TestClient(incident_app.app) as client:
        page = client.get("/")

    assert page.status_code == 200
    assert 'data-agent-filter="metrics"' in page.text
    assert 'data-agent-filter="traces"' in page.text
    assert 'data-target="incident-report-panel"' in page.text
    assert "http://localhost:9090" not in page.text
    assert "http://localhost:3000" not in page.text


def test_dashboard_lists_saved_reports_and_incident_scoped_agent_events(
    monkeypatch, tmp_path: Path
) -> None:
    report_dir = tmp_path / "incidents"
    report_dir.mkdir()
    (report_dir / "incident-one.md").write_text(
        "# Incident investigation: InventoryFailure\n\n"
        "- Incident ID: `incident-one`\n"
        "- Service: `inventory`\n"
        "- Summary: Injected inventory error\n"
        "- Action: `restart`\n"
        "- Command: `kubectl rollout restart deployment/inventory -n sre`\n"
        "- Reasoning: A validated error signal was observed.\n"
        "- Risk: **medium**\n",
        encoding="utf-8",
    )
    log_path = tmp_path / "agent-events.jsonl"
    events = [
        {
            "timestamp": "2026-01-01T00:00:00Z",
            "agent": "metrics",
            "input": {"alert": {"incident_id": "incident-one"}},
            "output": {"status": "complete"},
        },
        {
            "timestamp": "2026-01-01T00:00:01Z",
            "agent": "metrics",
            "input": {"alert": {"incident_id": "incident-two"}},
            "output": {"status": "complete"},
        },
    ]
    log_path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(incident_app, "incidents", {})
    monkeypatch.setenv("INCIDENT_REPORT_DIR", str(report_dir))
    monkeypatch.setenv("AGENT_LOG_PATH", str(log_path))

    with TestClient(incident_app.app) as client:
        incidents = client.get("/api/incidents")
        agent_events = client.get("/api/incidents/incident-one/events")

    assert incidents.status_code == 200
    assert incidents.json()["incidents"][0]["incident_id"] == "incident-one"
    assert incidents.json()["incidents"][0]["service"] == "inventory"
    assert incidents.json()["incidents"][0]["remediation"]["action"] == "restart"
    assert incidents.json()["incidents"][0]["remediation"]["command"].startswith("kubectl ")
    assert agent_events.status_code == 200
    assert agent_events.json()["total_events"] == 1
    assert agent_events.json()["events"][0]["agent"] == "metrics"


def test_runbook_capability_requires_kubernetes_and_approval_token(monkeypatch) -> None:
    monkeypatch.setattr(incident_app.kubernetes, "apps_api", None)
    monkeypatch.setenv("APPROVAL_TOKEN", "test-token")

    with TestClient(incident_app.app) as client:
        capabilities = client.get("/api/capabilities")

    assert capabilities.status_code == 200
    assert capabilities.json() == {
        "kubernetes_available": False,
        "approval_configured": True,
        "runbooks_available": False,
    }
