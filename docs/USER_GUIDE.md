# Local User Guide

This guide covers the Docker Compose deployment on Windows PowerShell. It explains
the prerequisites, how to start and stop the stack, where to explore it, and how
to verify an incident from request to report.

The Incident Commander dashboard at `http://localhost:8000/` is the main place
to review investigations. The API documentation, Grafana, Prometheus, Jaeger,
and generated Markdown reports provide deeper inspection.

## Dependencies

| Dependency | Required for | Notes |
|---|---|---|
| Docker Desktop with the Linux engine | Running the application | Compose builds four Python 3.11 images and downloads the observability images. |
| Docker Compose v2 plugin | Starting and managing containers | Run `docker compose version` to check availability. |
| Python 3.11 | Local tests and development | Not required to run the application containers. |
| Ollama and a local model | Local LLM-based RCA | Optional; the default `mock` provider needs no model or key. |
| `kind` and `kubectl` | Kubernetes deployment | Optional; not needed for Compose. See the [kind instructions](../README.md#kind). |

Dependency manifests:

- `requirements-app.txt`: FastAPI services, HTTP client, and OpenTelemetry packages.
- `requirements-agent.txt`: the app dependencies plus the Kubernetes client for
  incident investigation and kind runbooks.
- `requirements-dev.txt`: the agent dependencies plus pytest, Ruff, and httpx.

Prometheus, Alertmanager, Grafana, Jaeger, and the OpenTelemetry Collector run as
Compose services. Ollama is not a Compose service; the Incident Commander reaches
the Ollama process running on the host through `host.docker.internal`.

## Configure the environment

From the project directory, create `.env` only if you do not already have one:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

The default `LLM_PROVIDER=mock` is the simplest way to get started. It does not
need an API key.

To use Ollama, first confirm the model is installed with `ollama list`, then set
these values in `.env`:

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=llama3.2:latest
LLM_API_KEY=ollama
```

`LLM_API_KEY` must be non-empty when `LLM_PROVIDER=openai`; `ollama` is a local
placeholder, not a hosted-provider credential. Change `LLM_MODEL` to a model
shown by `ollama list`. For runbook approval, generate a random value, for example
with `[guid]::NewGuid().ToString("N")`, and set it as `APPROVAL_TOKEN`. Keep
`.env` private and do not commit it.

Compose publishes its application and observability ports on `127.0.0.1` only.
The dashboard and APIs do not authenticate users, so do not change those
bindings to expose the stack to an untrusted network.

## Start the application

Build and start all services in the background:

```powershell
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Wait until the application containers report healthy. Some infrastructure
containers have no Docker healthcheck, so verify their HTTP readiness endpoints
as well:

```powershell
$urls = @(
  'http://localhost:8000/healthz',
  'http://localhost:8001/readyz',
  'http://localhost:8002/readyz',
  'http://localhost:8003/readyz',
  'http://localhost:9090/-/ready',
  'http://localhost:9093/-/ready',
  'http://localhost:3000/api/health',
  'http://localhost:16686/'
)
foreach ($url in $urls) {
  $response = Invoke-WebRequest -Uri $url -TimeoutSec 10 -UseBasicParsing
  "$($response.StatusCode) $url"
}
```

Each URL should return HTTP 200. If Compose reports a port conflict or a
container exits, inspect it with `docker compose ps --all` and
`docker compose logs <service>`.

## Navigate the application

| What to inspect | URL or command | What it shows |
|---|---|---|
| Incident dashboard | http://localhost:8000/ | Saved and current incidents, investigation reports, structured agent logs, RCA evidence, and suggested commands. |
| Incident Commander API | http://localhost:8000/docs | Alert ingestion, incident reports, resolution, and approval endpoints. |
| Orders API | http://localhost:8001/docs | Place an order; Orders calls Payments and Inventory. |
| Payments API | http://localhost:8002/docs | Payment service routes and health checks. |
| Inventory API | http://localhost:8003/docs | Inventory routes, health checks, and chaos controls. |
| Grafana | http://localhost:3000 | Provisioned SRE dashboard. Default local login: `admin` / `sre-local-only`. |
| Prometheus | http://localhost:9090 | Query metrics, recording rules, alert state, and scrape targets. |
| Alertmanager | http://localhost:9093 | Inspect alert groups and configured webhook receiver. |
| Jaeger | http://localhost:16686 | Search traces by service and inspect spans. |
| Incident report | `python -m incident_commander.cli show <incident_id>` | Print the saved investigation report. |

Select an incident in the dashboard to view its report and agent events. The
Remediation panel displays the suggested action, reasoning, and risk. **Copy
command** copies the suggestion but never executes it. Saved reports and their
historical suggestions remain visible after a container restart, but archived
commands are not re-evaluated, cannot be copied, and cannot be approved. The
approval flow is available only for current in-memory incidents when Kubernetes
access and `APPROVAL_TOKEN` are configured.

The Prometheus, Grafana/SLO, Jaeger, and Alertmanager shortcuts navigate within
the selected incident: metrics and trace shortcuts filter its agent events, the
Grafana/SLO shortcut opens its report, and the Alertmanager shortcut returns to
the incident summary. The remediation command follows separate evidence rules,
independently from the LLM-generated RCA ranking. Rollback requires cited rollout
evidence, scale requires saturation, and restart requires an explicit process
failure in logs. A high error ratio alone will not suggest a restart; if the
evidence does not establish a safe action, the dashboard says no runbook command
is supported.

In the default Compose deployment, Kubernetes access is disabled, so the
dashboard reports that runbook approvals are unavailable. This is expected: the
Remediation Agent only suggests commands, and it does not run them. Use the kind
deployment to enable Kubernetes evidence and the explicit human-approval
runbooks. The approval form requires an approver name, approval token, and
confirmation before sending an action.

The OpenAPI pages also describe request schemas. The primary service route is
`POST /orders` with an `item_id` and a `quantity` from 1 to 100. A successful
response contains the order ID, approved payment, and inventory reservation.

Useful Prometheus expressions include:

```promql
app_requests_total
service:error_ratio:rate5m
service:availability:ratio_rate5m
service:latency:p95_5m
```

The Grafana dashboard visualizes the same service-level signals. The SLO target
is 99.5% availability; the starter p95 warning threshold is 500 ms.

## Verify normal service traffic

Submit an order:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8001/orders `
  -ContentType 'application/json' `
  -Body '{"item_id":"widget","quantity":2}'
```

Expect a JSON response with `payment.status` equal to `approved` and
`reservation.status` equal to `reserved`. The request should create metrics and
traces for the service path.

## Run the end-to-end incident demo

The demo turns on bounded Inventory error injection, observes the resulting
Orders HTTP 502, and makes additional requests until Prometheus records an error
ratio. It then submits a synthetic firing webhook to the Incident Commander,
waits for the multi-agent analysis, and submits a resolved webhook to create a
postmortem. The configured long burn-rate windows are not expected to fire during
this short demo.

Run it from the project directory:

```powershell
python scripts/demo.py
```

The script explicitly turns chaos off after the Prometheus wait, including if
that wait fails. It prints an incident fingerprint such as `demo-...`. Use that
ID to print the report:

```powershell
python -m incident_commander.cli show <incident_id>
```

Generated files are stored on the host under:

- `artifacts/incidents/`: per-agent findings, RCA evidence citations, manual
  command suggestion, and SLO impact.
- `artifacts/postmortems/`: resolution timeline, available SLO impact, root-cause
  hypothesis, and corrective actions.
- `artifacts/agent-events.jsonl`: structured inputs and outputs for each agent.
- `artifacts/audit.jsonl`: human-approved runbook requests and outcomes.

### What a successful demo looks like

1. The demo reports an injected Inventory error and an Orders HTTP 502.
2. Prometheus returns a nonzero `service:error_ratio:rate5m` for Inventory.
3. `POST /alerts` returns an analyzed incident with four evidence-agent outputs,
   an RCA hypothesis with evidence IDs, a remediation suggestion, and a report
   path.
4. The resolved webhook reports `postmortem_generated`.
5. `show <incident_id>` prints the Markdown investigation report.
6. A subsequent normal order succeeds, confirming the chaos setting is off.

## Logs and troubleshooting

Follow service logs:

```powershell
docker compose logs -f incident-commander
docker compose logs -f orders inventory payments
docker compose logs -f otel-collector prometheus
```

Common issues:

| Symptom | Check |
|---|---|
| Containers do not start | Confirm Docker Desktop is running, then inspect `docker compose ps --all` and `docker compose logs <service>`. |
| A local port is already in use | Stop the process using that port or change the corresponding host port in `docker-compose.yml`. |
| Ollama-backed analysis cannot connect | Confirm Ollama is running, the model appears in `ollama list`, and `.env` uses `http://host.docker.internal:11434/v1`. Set `LLM_PROVIDER=mock` temporarily to isolate model connectivity. |
| Demo waits for a Prometheus error sample | Check `http://localhost:9090/targets` and `docker compose logs otel-collector prometheus`; the demo needs exported request metrics before it submits the alert. |
| Logs, events, or rollout evidence are unavailable | This is expected in Compose: Kubernetes evidence collection is disabled. Use kind for Kubernetes evidence. |
| A trace agent reports no spans | Check Jaeger and OTLP Collector health and submit normal service traffic before searching traces. Missing trace evidence is reported as unavailable; it does not prevent the other agents from investigating. |
| An approved runbook action fails | Runbooks need access to the project kind cluster. Compose does not provide Kubernetes credentials; no automatic fallback is performed. |

## Stop or restart the application

Stop containers but leave them available for a quick restart:

```powershell
docker compose stop
```

Restart stopped containers:

```powershell
docker compose start
```

Stop and remove the Compose containers and network:

```powershell
docker compose down
```

`docker compose down` does not delete `.env` or the host-side `artifacts`
directory. Start the stack again with `docker compose up -d`.

## Local development checks

For a local Python development environment, Python 3.11 is recommended:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\ruff.exe format --check .
```

The Compose deployment itself does not depend on the host virtual environment.
For the optional Kubernetes deployment and its prerequisites, follow the
[kind section in the README](../README.md#kind). In Compose, Kubernetes evidence
collection is disabled; in kind, the Incident Commander can inspect cluster
evidence. Remediation always requires separate explicit human approval.
