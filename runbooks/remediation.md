# Human-approved remediation runbooks

Runbooks are deliberately limited to the `orders`, `payments`, and `inventory`
Deployments in the `sre` namespace. The incident service never invokes an action
because an alert fired; an operator must confirm in the CLI and the API must
receive the configured `X-Approval-Token`. Every request and outcome is written
to the JSONL audit log.

Before any action:

1. Read the incident evidence, recent rollout history, and the current SLO state.
2. Confirm the affected service and expected impact with the on-call operator.
3. Use the smallest action that addresses the verified failure mode.
4. Verify pod readiness, error rate, p95 latency, and error-budget burn after acting.

## Rollout restart

Use only when a transient stuck process or lost connection state is supported by
evidence. Restarting a deployment replaces its pod template annotation and lets
the normal rollout strategy replace pods.

```powershell
python -m incident_commander.cli restart inventory --approver "Your Name"
```

Verify `kubectl rollout status deployment/inventory -n sre` and inspect the
service dashboard before declaring recovery.

## Scale up

Use only when resource saturation or capacity pressure is supported by telemetry.
The API accepts explicit replica counts from 2 through 10; it does not autoscale.

```powershell
python -m incident_commander.cli scale orders --replicas 2 --approver "Your Name"
```

Verify the rollout and resource usage, then reduce replicas manually if the
temporary capacity is no longer needed.

## Roll back

Use when a recent ReplicaSet revision is correlated with the incident and the
previous revision is known to be safer. The API patches the Deployment template
to the immediately preceding ReplicaSet owned by that Deployment; it does not
delete history or roll back unrelated resources.

```powershell
python -m incident_commander.cli rollback payments --approver "Your Name"
```

Verify `kubectl rollout status deployment/payments -n sre`, compare the live
image with the intended revision, and confirm the SLO signals have recovered.
