# Limitations and Design Trade-offs

SRE Incident Commander is a local portfolio demo, not a production incident
management system. Its safeguards and observability illustrate useful patterns,
but do not replace production identity, security, persistence, or operational
controls.

## Known limitations

### Local trust boundary

- Docker Compose binds published ports to `127.0.0.1`, which keeps them local to
  the host by default. The dashboard, incident read APIs, and alert webhook do
  not authenticate users, so do not change the bindings to expose the stack to
  an untrusted network.
- The runbook endpoint checks a shared `APPROVAL_TOKEN` and an approval
  confirmation. The typed approver name is not an identity check. The audit
  JSONL file is local and is not tamper-proof.
- Compose uses a published demo Grafana credential. Replace it before sharing
  the stack or using it outside a disposable local environment.
- Secret redaction covers common credential patterns, not every form of
  personal or sensitive data. Review telemetry and provider data-handling
  requirements before sending evidence to a hosted LLM.

### Evidence and diagnosis

- Kubernetes evidence collection is disabled in Compose. Pod logs, Kubernetes
  events, and rollout history require the kind deployment; they are reported as
  unavailable rather than inferred.
- Traces depend on the request having produced spans and Jaeger retaining them
  for the queried time range. Missing traces reduce evidence but do not prove
  that a service is healthy.
- RCA hypotheses are generated from the collected evidence and validated
  citations. A valid citation does not prove causation, and model confidence is
  not calibrated as a probability of root-cause correctness.
- The 99.5% availability objective, latency threshold, recording rules, and
  burn-rate windows are illustrative defaults. Tune them to a real service's
  traffic, measurement window, and user impact before relying on them.

### LLM behavior

- The mock provider is deterministic test scaffolding, not an RCA model.
  Ollama or another OpenAI-compatible provider can produce different rankings
  for the same evidence.
- The provider asks for structured JSON and makes one correction attempt when
  the response does not match the schema. If validation still fails, analysis
  fails explicitly; it does not silently substitute mock output.
- Only cited telemetry is passed to the RCA ranking, but evidence can be
  incomplete, stale, noisy, or insufficient to distinguish a symptom from a
  cause.

### Remediation and approval

- Remediation is rule-based and deliberately narrow: rollback requires cited
  rollout evidence, scale requires resource-saturation evidence, and restart
  requires an explicit process-failure signal. A high error ratio alone is not
  enough to recommend a restart; some incidents therefore have no corrective
  command.
- The Remediation Agent only suggests commands. Execution is separate, requires
  explicit approval, and is available only when Kubernetes access and the
  approval token are configured. Compose does not provide Kubernetes access.
- The runbooks cover only restart, scale, and rollback. They do not verify
  application-level recovery or replace an operator's judgment.

### State and retention

- Active incident state is held in process memory. After an application restart,
  saved reports remain readable, but archived recommendations are historical
  and cannot be copied or approved as current actions.
- Compose stores reports, postmortems, and JSONL logs under the ignored local
  `artifacts/` directory. Agent inputs and outputs are appended without an
  automatic retention or rotation policy, so this directory can grow large and
  may contain operational telemetry. Do not commit it.
- The kind deployment mounts incident data on `emptyDir`; data is lost when the
  pod is replaced. Prometheus and Jaeger also have no persistent storage
  configured in the starter Compose stack.
- These services are single-instance demo components: there is no HA,
  disaster-recovery plan, or tested backup/restore procedure.

## Design choices and trade-offs

| Choice | Benefit | Cost or limitation |
|---|---|---|
| Docker Compose first, with kind manifests | Quick local startup and a path to exercise Kubernetes APIs | Compose cannot provide pod/change evidence or runbooks; kind requires extra setup |
| Local Ollama and a pluggable provider interface | Local inference can avoid sending telemetry to a hosted model; adapters can be swapped | Model latency and output quality vary; hosted providers require a separate data review |
| Typed agent schemas, telemetry validation, and exact evidence citations | Rejects malformed or unsupported findings before RCA uses them | Valid evidence can still be incomplete and citations cannot establish causation |
| Deterministic, human-approved runbooks | Predictable, reviewable actions with an audit trail; no LLM execution | Only a few evidence patterns and actions are supported; uncertain incidents may get no command |
| Markdown reports and JSONL agent/audit logs | Easy to inspect, replay, and include in a portfolio demo | No indexing, retention, tamper-proof audit storage, or efficient long-term querying |
| In-memory active state with saved read-only reports | Minimal infrastructure and safe behavior after restart | Approval context is not reconstructed from archived reports |
| Synthetic telemetry fixtures and short local SLO windows | Fast, repeatable tests and demos | They do not represent production traffic or certify SLO behavior |

## Before broader use

Add authentication and TLS, restrict network exposure, replace demo credentials,
use a secrets manager, persist and rotate state/logs, define identity-bound
approvals, test recovery and backups, and evaluate model behavior against
representative incidents. Keep remediation human-approved unless a separate,
well-tested production control plane is introduced.
