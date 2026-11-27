from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import requests
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException

from incident_commander.models import Evidence

_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(authorization|password|passwd|token|secret|api[_-]?key)"
        r"(\s*[:=]\s*)(?:bearer\s+)?([^\s,;]+)"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
)


def redact_sensitive(text: str) -> str:
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            redacted = pattern.sub(r"\1\2[REDACTED]", redacted)
        else:
            redacted = pattern.sub("Bearer [REDACTED]", redacted)
    return redacted


class PrometheusEvidenceCollector:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("PROMETHEUS_URL", "http://prometheus:9090")).rstrip(
            "/"
        )

    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        service = str(alert.get("service", ""))
        if service not in {"orders", "payments", "inventory"}:
            return [
                Evidence(
                    evidence_id="prometheus-service-unknown",
                    source="system",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement=(
                        "Alert did not identify a supported service; "
                        "service-specific queries were skipped."
                    ),
                )
            ]
        escaped_service = service.replace("\\", "\\\\").replace('"', '\\"')
        queries = {
            "availability": f'service:availability:ratio_rate5m{{service="{escaped_service}"}}',
            "error-ratio": f'service:error_ratio:rate5m{{service="{escaped_service}"}}',
            "p95-latency": f'service:latency:p95_5m{{service="{escaped_service}"}}',
        }
        evidence: list[Evidence] = []
        for name, query in queries.items():
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/query",
                    params={"query": query},
                    timeout=5,
                )
                response.raise_for_status()
                payload = response.json()
                if payload.get("status") != "success":
                    raise ValueError(f"Prometheus query returned status {payload.get('status')!r}.")
                results = payload["data"]["result"]
                if not results:
                    evidence.append(
                        Evidence(
                            evidence_id=f"prometheus-{name}",
                            source="prometheus",
                            observed_at=datetime.now(UTC).isoformat(),
                            statement=(
                                f"No Prometheus sample is available for {name} for {service}."
                            ),
                        )
                    )
                    continue
                timestamp, raw_value = results[0]["value"]
                value = float(raw_value)
                statement = {
                    "availability": f"Five-minute availability for {service} is {value:.6f}.",
                    "error-ratio": f"Five-minute error ratio for {service} is {value:.6f}.",
                    "p95-latency": f"Five-minute p95 latency for {service} is {value:.6f} seconds.",
                }[name]
                evidence.append(
                    Evidence(
                        evidence_id=f"prometheus-{name}",
                        source="prometheus",
                        observed_at=datetime.fromtimestamp(float(timestamp), UTC).isoformat(),
                        statement=statement,
                        value=value,
                    )
                )
            except (requests.RequestException, ValueError, KeyError, TypeError) as error:
                evidence.append(
                    Evidence(
                        evidence_id=f"prometheus-{name}",
                        source="system",
                        observed_at=datetime.now(UTC).isoformat(),
                        statement=f"Prometheus {name} query failed: {redact_sensitive(str(error))}",
                    )
                )
        return evidence


class KubernetesEvidenceCollector:
    def __init__(self) -> None:
        self.namespace = os.getenv("KUBERNETES_NAMESPACE", "sre")
        self.core_api: client.CoreV1Api | None = None
        self.apps_api: client.AppsV1Api | None = None
        self.unavailable_reason: str | None = None
        if os.getenv("KUBERNETES_ENABLED", "true").lower() in {"false", "0", "no"}:
            self.unavailable_reason = "Kubernetes evidence collection is disabled by configuration."
            return
        try:
            if os.getenv("KUBERNETES_SERVICE_HOST"):
                config.load_incluster_config()
            else:
                config.load_kube_config()
            self.core_api = client.CoreV1Api()
            self.apps_api = client.AppsV1Api()
        except ConfigException as error:
            self.unavailable_reason = f"Kubernetes client configuration failed: {error}"

    def collect(self, alert: dict[str, object]) -> list[Evidence]:
        if self.core_api is None or self.apps_api is None:
            return [
                Evidence(
                    evidence_id="kubernetes-unavailable",
                    source="system",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement=self.unavailable_reason or "Kubernetes client is unavailable.",
                )
            ]
        service = str(alert.get("service", ""))
        if service not in {"orders", "payments", "inventory"}:
            return [
                Evidence(
                    evidence_id="kubernetes-service-unknown",
                    source="system",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement=(
                        "Alert did not identify a supported service; "
                        "Kubernetes resource queries were skipped."
                    ),
                )
            ]
        alert_start, alert_end = self._alert_window(alert)
        evidence: list[Evidence] = []
        try:
            pods = self.core_api.list_namespaced_pod(
                self.namespace, label_selector=f"app={service}", limit=20
            ).items
        except ApiException as error:
            evidence.append(self._api_error("kubernetes-pods-error", "pod list", error))
            pods = []
        if not pods and not any(item.evidence_id == "kubernetes-pods-error" for item in evidence):
            evidence.append(
                Evidence(
                    evidence_id="kubernetes-pods-empty",
                    source="system",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement=f"No pods matched app={service} in namespace {self.namespace}.",
                )
            )
        pod_names = {pod.metadata.name for pod in pods if pod.metadata and pod.metadata.name}
        for pod in pods[:5]:
            if not pod.metadata or not pod.metadata.name:
                continue
            container_states: list[str] = []
            for status in pod.status.container_statuses or [] if pod.status else []:
                if status.last_state and status.last_state.terminated:
                    terminated = status.last_state.terminated
                    container_states.append(
                        f"{status.name} last terminated with reason={terminated.reason}, "
                        f"exit_code={terminated.exit_code}"
                    )
            phase = pod.status.phase if pod.status else "unknown"
            restarts = (
                sum(item.restart_count for item in pod.status.container_statuses or [])
                if pod.status
                else 0
            )
            pod_state = f"Pod {pod.metadata.name} phase={phase}, restarts={restarts}."
            evidence.append(
                Evidence(
                    evidence_id=f"pod-{pod.metadata.name}",
                    source="pod",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement=redact_sensitive(pod_state + " " + "; ".join(container_states)),
                )
            )
            try:
                raw_logs = self.core_api.read_namespaced_pod_log(
                    name=pod.metadata.name,
                    namespace=self.namespace,
                    tail_lines=100,
                    timestamps=True,
                    since_time=alert_start - timedelta(minutes=5),
                )
                logs = redact_sensitive(raw_logs[-10_000:])
                if logs.strip():
                    evidence.append(
                        Evidence(
                            evidence_id=f"logs-{pod.metadata.name}",
                            source="pod_log",
                            observed_at=datetime.now(UTC).isoformat(),
                            statement=logs,
                        )
                    )
                else:
                    evidence.append(
                        Evidence(
                            evidence_id=f"logs-{pod.metadata.name}",
                            source="system",
                            observed_at=datetime.now(UTC).isoformat(),
                            statement=f"No recent pod logs were returned for {pod.metadata.name}.",
                        )
                    )
            except ApiException as error:
                evidence.append(
                    self._api_error(f"logs-{pod.metadata.name}-error", "pod log read", error)
                )

        try:
            events = self.core_api.list_namespaced_event(self.namespace, limit=500).items
            cutoff = alert_start - timedelta(minutes=60)
            related_events = [
                event
                for event in events
                if event.involved_object
                and (
                    event.involved_object.name in pod_names
                    or event.involved_object.kind == "ReplicaSet"
                    and service in (event.involved_object.name or "")
                )
                and cutoff <= self._event_time(event) <= alert_end + timedelta(minutes=5)
            ]
            for index, event in enumerate(related_events[-50:]):
                evidence.append(
                    Evidence(
                        evidence_id=f"event-{index + 1}",
                        source="event",
                        observed_at=self._event_time(event).isoformat(),
                        statement=redact_sensitive(
                            f"Event {event.type or 'unknown'} {event.reason or ''}: "
                            f"{event.message or ''}"
                        ),
                    )
                )
            if not related_events:
                evidence.append(
                    Evidence(
                        evidence_id="kubernetes-events-empty",
                        source="system",
                        observed_at=datetime.now(UTC).isoformat(),
                        statement=(
                            "No related Kubernetes events were found in "
                            f"namespace {self.namespace}."
                        ),
                    )
                )
        except ApiException as error:
            evidence.append(self._api_error("kubernetes-events-error", "event list", error))

        try:
            replica_sets = self.apps_api.list_namespaced_replica_set(
                self.namespace, label_selector=f"app={service}", limit=100
            ).items
            owned_sets = [
                replica_set
                for replica_set in replica_sets
                if replica_set.metadata
                and any(
                    owner.kind == "Deployment" and owner.name == service
                    for owner in replica_set.metadata.owner_references or []
                )
            ]
            owned_sets.sort(
                key=lambda item: item.metadata.creation_timestamp
                or datetime.min.replace(tzinfo=UTC),
                reverse=True,
            )
            if not owned_sets:
                evidence.append(
                    Evidence(
                        evidence_id="kubernetes-rollouts-empty",
                        source="system",
                        observed_at=datetime.now(UTC).isoformat(),
                        statement=f"No ReplicaSets owned by deployment {service} were found.",
                    )
                )
            for index, replica_set in enumerate(owned_sets[:10]):
                metadata = replica_set.metadata
                if metadata is None:
                    continue
                created = metadata.creation_timestamp or datetime.now(UTC)
                revision = (metadata.annotations or {}).get(
                    "deployment.kubernetes.io/revision", "unknown"
                )
                images = [
                    container.image
                    for container in (
                        replica_set.spec.template.spec.containers
                        if replica_set.spec
                        and replica_set.spec.template
                        and replica_set.spec.template.spec
                        else []
                    )
                ]
                recent = created >= datetime.now(UTC) - timedelta(hours=1)
                description = (
                    f"{'Recent rollout' if recent else 'Prior rollout'} for {service}: "
                    f"ReplicaSet {metadata.name}, revision={revision}, "
                    f"created={created.isoformat()}, "
                    f"images={images}."
                )
                evidence.append(
                    Evidence(
                        evidence_id=f"deployment-{index + 1}",
                        source="deployment",
                        observed_at=created.isoformat(),
                        statement=redact_sensitive(description),
                    )
                )
        except ApiException as error:
            evidence.append(self._api_error("kubernetes-rollouts-error", "ReplicaSet list", error))
        return evidence

    def collect_changes(self, alert: dict[str, object]) -> list[Evidence]:
        if self.apps_api is None or self.core_api is None:
            return [
                Evidence(
                    evidence_id="kubernetes-changes-unavailable",
                    source="system",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement=self.unavailable_reason or "Kubernetes client is unavailable.",
                )
            ]
        service = str(alert.get("service", ""))
        if service not in {"orders", "payments", "inventory"}:
            return [
                Evidence(
                    evidence_id="kubernetes-changes-service-unknown",
                    source="system",
                    observed_at=datetime.now(UTC).isoformat(),
                    statement="Alert did not identify a supported service.",
                )
            ]
        alert_start, alert_end = self._alert_window(alert)
        evidence: list[Evidence] = []
        try:
            deployments = self.apps_api.list_namespaced_deployment(
                self.namespace, label_selector=f"app={service}", limit=20
            ).items
            for deployment in deployments:
                if not deployment.metadata:
                    continue
                updated = max(
                    (
                        condition.last_update_time
                        for condition in (deployment.status.conditions or [])
                        if condition.last_update_time
                    ),
                    default=deployment.metadata.creation_timestamp or datetime.now(UTC),
                )
                images = [
                    container.image
                    for container in (
                        deployment.spec.template.spec.containers
                        if deployment.spec
                        and deployment.spec.template
                        and deployment.spec.template.spec
                        else []
                    )
                ]
                evidence.append(
                    Evidence(
                        evidence_id=f"deployment-current-{deployment.metadata.name}",
                        source="deployment",
                        observed_at=updated.isoformat(),
                        statement=redact_sensitive(
                            f"Deployment {deployment.metadata.name} observed at "
                            f"{updated.isoformat()}, generation="
                            f"{deployment.metadata.generation}, images={images}."
                        ),
                    )
                )
            config_maps = self.core_api.list_namespaced_config_map(
                self.namespace, label_selector=f"app={service}", limit=50
            ).items
            for config_map in config_maps:
                if not config_map.metadata:
                    continue
                created = config_map.metadata.creation_timestamp or datetime.now(UTC)
                evidence.append(
                    Evidence(
                        evidence_id=f"configmap-{config_map.metadata.name}",
                        source="deployment",
                        observed_at=created.isoformat(),
                        statement=redact_sensitive(
                            f"ConfigMap {config_map.metadata.name} metadata observed; "
                            f"created={created.isoformat()}, "
                            f"resource_version={config_map.metadata.resource_version}."
                        ),
                    )
                )
            replica_sets = self.apps_api.list_namespaced_replica_set(
                self.namespace, label_selector=f"app={service}", limit=100
            ).items
            owned_sets = [
                item
                for item in replica_sets
                if item.metadata
                and any(
                    owner.kind == "Deployment" and owner.name == service
                    for owner in item.metadata.owner_references or []
                )
            ]
            owned_sets.sort(
                key=lambda item: item.metadata.creation_timestamp
                or datetime.min.replace(tzinfo=UTC),
                reverse=True,
            )
            for index, replica_set in enumerate(owned_sets[:10]):
                metadata = replica_set.metadata
                if metadata is None:
                    continue
                created = metadata.creation_timestamp or datetime.now(UTC)
                revision = (metadata.annotations or {}).get(
                    "deployment.kubernetes.io/revision", "unknown"
                )
                recent = (
                    alert_start - timedelta(hours=1) <= created <= alert_end + timedelta(minutes=5)
                )
                evidence.append(
                    Evidence(
                        evidence_id=f"changes-replicaset-{index + 1}",
                        source="deployment",
                        observed_at=created.isoformat(),
                        statement=redact_sensitive(
                            f"{'Recent rollout' if recent else 'Prior rollout'} for "
                            f"{service}: ReplicaSet {metadata.name}, revision={revision}, "
                            f"created={created.isoformat()}."
                        ),
                    )
                )
        except ApiException as error:
            evidence.append(self._api_error("kubernetes-changes-error", "rollout query", error))

        try:
            events = self.core_api.list_namespaced_event(self.namespace, limit=500).items
            relevant = [
                event
                for event in events
                if event.involved_object
                and event.involved_object.kind in {"Deployment", "ReplicaSet", "ConfigMap"}
                and service in (event.involved_object.name or "")
                and alert_start - timedelta(hours=1)
                <= self._event_time(event)
                <= alert_end + timedelta(minutes=5)
            ]
            for index, event in enumerate(relevant[-50:]):
                evidence.append(
                    Evidence(
                        evidence_id=f"changes-event-{index + 1}",
                        source="event",
                        observed_at=self._event_time(event).isoformat(),
                        statement=redact_sensitive(
                            f"Change event {event.reason or ''}: {event.message or ''}"
                        ),
                    )
                )
            if not relevant:
                evidence.append(
                    Evidence(
                        evidence_id="changes-events-empty",
                        source="system",
                        observed_at=datetime.now(UTC).isoformat(),
                        statement=f"No recent change events found for {service}.",
                    )
                )
        except ApiException as error:
            evidence.append(
                self._api_error("kubernetes-changes-events-error", "change events", error)
            )
        return evidence

    def perform_action(
        self, action: str, service: str, replicas: int | None = None
    ) -> dict[str, object]:
        if self.apps_api is None:
            raise RuntimeError(self.unavailable_reason or "Kubernetes client is unavailable.")
        namespace = self.namespace
        if action == "restart":
            restarted_at = datetime.now(UTC).isoformat()
            self.apps_api.patch_namespaced_deployment(
                service,
                namespace,
                {
                    "spec": {
                        "template": {
                            "metadata": {
                                "annotations": {"kubectl.kubernetes.io/restartedAt": restarted_at}
                            }
                        }
                    }
                },
            )
            return {"action": action, "service": service, "restarted_at": restarted_at}
        if action == "scale":
            if replicas is None:
                raise ValueError("The scale action requires an explicit replica count.")
            self.apps_api.patch_namespaced_deployment(
                service, namespace, {"spec": {"replicas": replicas}}
            )
            return {"action": action, "service": service, "replicas": replicas}
        if action != "rollback":
            raise ValueError(f"Unsupported runbook action: {action}")

        deployment = self.apps_api.read_namespaced_deployment(service, namespace)
        if not deployment.metadata or not deployment.metadata.uid:
            raise RuntimeError(f"Deployment {service} has no UID; rollback is unsafe.")
        replica_sets = self.apps_api.list_namespaced_replica_set(
            namespace, label_selector=f"app={service}", limit=100
        ).items
        owned_sets = [
            item
            for item in replica_sets
            if item.metadata
            and any(
                owner.kind == "Deployment" and owner.uid == deployment.metadata.uid
                for owner in item.metadata.owner_references or []
            )
        ]
        owned_sets.sort(
            key=lambda item: int(
                (item.metadata.annotations or {}).get("deployment.kubernetes.io/revision", "0")
            )
            if item.metadata
            else 0
        )
        if len(owned_sets) < 2:
            raise RuntimeError(f"No previous ReplicaSet revision is available for {service}.")
        previous = owned_sets[-2]
        if previous.spec is None or previous.spec.template is None or previous.metadata is None:
            raise RuntimeError("Previous ReplicaSet does not contain a pod template.")
        template = self.apps_api.api_client.sanitize_for_serialization(previous.spec.template)
        self.apps_api.patch_namespaced_deployment(
            service, namespace, {"spec": {"template": template}}
        )
        return {
            "action": action,
            "service": service,
            "rolled_back_to_revision": (previous.metadata.annotations or {}).get(
                "deployment.kubernetes.io/revision", "unknown"
            ),
        }

    @staticmethod
    def _event_time(event: Any) -> datetime:
        event_time = event.event_time or event.last_timestamp or event.first_timestamp
        if event_time is None:
            return datetime.now(UTC)
        if event_time.tzinfo is None:
            return event_time.replace(tzinfo=UTC)
        return event_time.astimezone(UTC)

    @staticmethod
    def _alert_window(alert: dict[str, object]) -> tuple[datetime, datetime]:
        now = datetime.now(UTC)
        try:
            start_value = str(alert.get("startsAt", ""))
            start = datetime.fromisoformat(start_value.replace("Z", "+00:00"))
            end_value = str(alert.get("endsAt", ""))
            end = (
                datetime.fromisoformat(end_value.replace("Z", "+00:00"))
                if end_value and not end_value.startswith("0001-01-01")
                else now
            )
            if start.tzinfo is None or end.tzinfo is None or end < start:
                raise ValueError("Invalid alert time bounds.")
            return start.astimezone(UTC), end.astimezone(UTC)
        except ValueError:
            return now - timedelta(minutes=5), now

    @staticmethod
    def _api_error(evidence_id: str, operation: str, error: ApiException) -> Evidence:
        return Evidence(
            evidence_id=evidence_id,
            source="system",
            observed_at=datetime.now(UTC).isoformat(),
            statement=f"Kubernetes {operation} failed with HTTP {error.status}: {error.reason}.",
        )
