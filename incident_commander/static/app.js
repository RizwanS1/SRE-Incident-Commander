const incidentList = document.getElementById("incident-list");
const emptyInbox = document.getElementById("empty-inbox");
const apiStatus = document.getElementById("api-status");
const refreshButton = document.getElementById("refresh-button");
const welcome = document.getElementById("welcome");
const selectedIncident = document.getElementById("selected-incident");
const approvalForm = document.getElementById("approval-form");
const actionResult = document.getElementById("action-result");
const incidentNavigation = document.querySelectorAll(".quick-links button");

let incidents = [];
let incidentEvents = [];
let eventsTruncated = false;
let totalEvents = 0;
let currentAgentFilter = "all";
let capabilities = {
  kubernetes_available: false,
  approval_configured: false,
  runbooks_available: false,
};
let currentIncident = null;

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.detail || `Request failed with HTTP ${response.status}`);
  }
  return body;
}

function setApiStatus(online, message) {
  apiStatus.textContent = message;
  apiStatus.className = `status-pill ${online ? "status-healthy" : "status-pending"}`;
}

function renderIncidentList() {
  incidentList.replaceChildren();
  document.getElementById("incident-count").textContent = String(incidents.length);
  emptyInbox.hidden = incidents.length > 0;

  for (const incident of incidents) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "incident-item";
    button.setAttribute(
      "aria-current",
      currentIncident?.incident_id === incident.incident_id ? "true" : "false",
    );

    const title = document.createElement("strong");
    title.textContent = incident.alert_name || "Incident";
    const meta = document.createElement("span");
    meta.textContent = `${incident.service || "unknown"} · ${incident.status.replaceAll("_", " ")}`;
    const id = document.createElement("span");
    id.textContent = incident.incident_id;
    button.append(title, meta, id);
    button.addEventListener("click", () => loadIncident(incident.incident_id));
    incidentList.append(button);
  }
}

function renderFilteredEvents() {
  const container = document.getElementById("event-list");
  container.replaceChildren();
  const filteredEvents =
    currentAgentFilter === "all"
      ? incidentEvents
      : incidentEvents.filter((event) => event.agent === currentAgentFilter);
  const count = document.getElementById("event-count");
  count.textContent =
    currentAgentFilter === "all"
      ? eventsTruncated
        ? `${filteredEvents.length} / ${totalEvents}`
        : String(filteredEvents.length)
      : `${filteredEvents.length} ${currentAgentFilter}`;

  if (filteredEvents.length === 0) {
    const message = document.createElement("p");
    message.className = "muted";
    message.textContent =
      currentAgentFilter === "all"
        ? "No structured agent events were recorded for this incident."
        : `No ${currentAgentFilter} agent events were recorded for this incident.`;
    container.append(message);
    return;
  }

  const agentLabels = {
    metrics: "Metrics Agent",
    logs: "Log Agent",
    changes: "Change Agent",
    traces: "Trace Agent",
    rca: "RCA Agent",
    remediation: "Remediation Agent",
  };
  const sourceLabels = {
    prometheus: "Prometheus",
    pod_log: "Kubernetes pod logs",
    event: "Kubernetes events",
    deployment: "Kubernetes rollout",
    trace: "Jaeger trace",
    system: "System status",
  };
  const fallbackSources = {
    metrics: "Prometheus query",
    logs: "Kubernetes logs and events",
    changes: "Kubernetes rollout history",
    traces: "Jaeger spans",
    rca: "LLM analysis",
    remediation: "Evidence-based rules",
  };
  const groups = new Map();
  for (const event of filteredEvents) {
    const agent = event.agent || "unknown";
    if (!groups.has(agent)) groups.set(agent, []);
    groups.get(agent).push(event);
  }

  for (const [agent, events] of groups) {
    const group = document.createElement("section");
    group.className = "event-agent-group";
    const heading = document.createElement("div");
    heading.className = "event-agent-heading";
    const title = document.createElement("h3");
    title.textContent = agentLabels[agent] || `${agent} agent`;
    const eventTotal = document.createElement("span");
    eventTotal.className = "count-badge";
    eventTotal.textContent = `${events.length} ${events.length === 1 ? "event" : "events"}`;
    heading.append(title, eventTotal);
    group.append(heading);

    const eventList = document.createElement("div");
    eventList.className = "event-agent-list";
    for (const event of events) {
      const output = event.output || {};
      const evidence = Array.isArray(output.evidence) ? output.evidence : [];
      const sources = [...new Set(evidence.map((item) => item.source).filter(Boolean))];
      const sourceNames = sources.length
        ? sources.map((source) => sourceLabels[source] || source)
        : [fallbackSources[agent] || "Agent activity"];
      const rawStatus = output.status || (output.agent ? "complete" : "recorded");
      const status = ["started", "complete", "partial", "unavailable", "failed"].includes(
        rawStatus,
      )
        ? rawStatus
        : "recorded";

      const details = document.createElement("details");
      details.className = "event-entry";
      const summary = document.createElement("summary");
      const owner = document.createElement("span");
      owner.className = "event-owner";
      owner.textContent = agentLabels[agent] || `${agent} agent`;
      const timestamp = document.createElement("span");
      timestamp.className = "event-timestamp";
      const date = new Date(event.timestamp || "");
      timestamp.textContent = Number.isNaN(date.getTime())
        ? "Time unavailable"
        : date.toLocaleString();
      const statusBadge = document.createElement("span");
      statusBadge.className = `event-status event-status-${status}`;
      statusBadge.textContent = status;
      const sourceBadges = document.createElement("span");
      sourceBadges.className = "event-source-list";
      for (const source of sourceNames) {
        const badge = document.createElement("span");
        badge.className = "event-source-badge";
        badge.textContent = source;
        sourceBadges.append(badge);
      }
      summary.append(owner, timestamp, statusBadge, sourceBadges);
      const body = document.createElement("pre");
      body.textContent = JSON.stringify(event, null, 2);
      details.append(summary, body);
      eventList.append(details);
    }
    group.append(eventList);
    container.append(group);
  }
}

function renderAgentStatuses(agentStatuses = []) {
  const container = document.getElementById("agent-statuses");
  container.replaceChildren();
  for (const item of agentStatuses) {
    const badge = document.createElement("span");
    badge.className = "agent-badge";
    badge.textContent = `${item.agent}: ${item.status}`;
    container.append(badge);
  }
}

function renderRemediation(incident) {
  const remediation = incident.remediation;
  const command = document.getElementById("suggested-command");
  const heading = document.getElementById("remediation-heading");
  const copyButton = document.getElementById("copy-command");
  const approveButton = document.getElementById("approve-button");
  const form = document.getElementById("approval-form");
  const risk = document.getElementById("risk-badge");
  actionResult.textContent = "";
  form.hidden = true;
  approveButton.hidden = true;
  copyButton.hidden = true;
  heading.textContent =
    incident.status === "saved_report" ? "Historical suggestion" : "Suggested remediation";

  if (!remediation) {
    command.textContent = "This saved report has no in-memory remediation suggestion.";
    document.getElementById("remediation-reasoning").textContent =
      "The report is available, but a process restart cleared the active incident state.";
    document.getElementById("remediation-status").textContent = "";
    risk.textContent = "";
    return;
  }

  document.getElementById("remediation-reasoning").textContent = remediation.reasoning;
  command.textContent = remediation.command || "No manual command was suggested.";
  copyButton.hidden = !remediation.command;
  risk.textContent = remediation.risk ? `Risk: ${remediation.risk}` : "";
  risk.className = `risk-badge risk-${remediation.risk || "low"}`;

  const status = document.getElementById("remediation-status");
  if (incident.status === "saved_report") {
    copyButton.hidden = true;
    status.textContent =
      remediation.command && remediation.action !== "none"
        ? "This command is preserved from an older report. It was not re-evaluated under the current policy and cannot be approved here. Select a fresh incident for a current recommendation."
        : "This archived report contains no current runbook command. Select a fresh incident for a current assessment.";
    return;
  }
  if (!remediation.command || remediation.action === "none") {
    status.textContent =
      "No evidence-validated runbook action was suggested. Continue investigating manually.";
    return;
  }

  if (!capabilities.runbooks_available) {
    const missing = [];
    if (!capabilities.kubernetes_available) missing.push("Kubernetes API access");
    if (!capabilities.approval_configured) missing.push("APPROVAL_TOKEN");
    status.textContent = `Runbook execution is disabled: configure ${missing.join(" and ") || "the runbook environment"}.`;
    return;
  }

  status.textContent =
    "This action is not automatic. Review the evidence, then explicitly approve it below.";
  approveButton.textContent = `Review and approve ${remediation.action}`;
  approveButton.hidden = false;
}

function renderEvents(events = [], truncated = false, total = events.length) {
  incidentEvents = events;
  eventsTruncated = truncated;
  totalEvents = total;
  renderFilteredEvents();
}

async function loadIncident(incidentId) {
  const incident = incidents.find((item) => item.incident_id === incidentId);
  if (!incident) return;
  if (currentIncident?.incident_id !== incidentId) {
    currentAgentFilter = "all";
    incidentEvents = [];
  }
  currentIncident = incident;
  incidentNavigation.forEach((button) => {
    button.disabled = false;
    if (button.dataset.agentFilter) {
      button.setAttribute(
        "aria-pressed",
        String(button.dataset.agentFilter === currentAgentFilter),
      );
    }
  });
  welcome.hidden = true;
  selectedIncident.hidden = false;
  renderIncidentList();

  document.getElementById("incident-service").textContent =
    `${incident.service || "unknown"} · ${incident.status.replaceAll("_", " ")}`;
  document.getElementById("incident-title").textContent = incident.alert_name || "Incident";
  document.getElementById("incident-summary").textContent = incident.summary || "No summary provided.";
  document.getElementById("incident-id").textContent = `Incident ID: ${incident.incident_id}`;
  document.getElementById("incident-state").textContent = incident.status.replaceAll("_", " ");
  document.getElementById("incident-state").className =
    `status-pill status-${incident.status}`;
  renderAgentStatuses(incident.agent_statuses);
  renderRemediation(incident);

  const reportUrl = `/incidents/${encodeURIComponent(incidentId)}/report`;
  document.getElementById("report-link").href = reportUrl;
  document.getElementById("incident-report").textContent = "Loading report...";
  document.getElementById("event-list").textContent = "Loading agent events...";

  const [reportResult, eventResult] = await Promise.allSettled([
    fetch(reportUrl).then(async (response) => {
      if (!response.ok) throw new Error(`Report request failed with HTTP ${response.status}`);
      return response.text();
    }),
    fetchJson(`/api/incidents/${encodeURIComponent(incidentId)}/events`),
  ]);

  document.getElementById("incident-report").textContent =
    reportResult.status === "fulfilled" ? reportResult.value : reportResult.reason.message;
  if (eventResult.status === "fulfilled") {
    renderEvents(
      eventResult.value.events,
      eventResult.value.truncated,
      eventResult.value.total_events,
    );
  } else {
    renderEvents();
    document.getElementById("event-list").firstElementChild.textContent =
      eventResult.reason.message;
  }
}

function navigateWithinIncident(button) {
  if (!currentIncident) return;
  const filter = button.dataset.agentFilter;
  if (filter) {
    currentAgentFilter = filter;
    incidentNavigation.forEach((item) => {
      if (item.dataset.agentFilter) {
        item.setAttribute("aria-pressed", String(item.dataset.agentFilter === filter));
      }
    });
    renderFilteredEvents();
    document.getElementById("agent-logs-panel").scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
    return;
  }

  document.getElementById(button.dataset.target).scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
}

async function refreshDashboard() {
  refreshButton.disabled = true;
  try {
    const [capabilityResult, incidentResult] = await Promise.all([
      fetchJson("/api/capabilities"),
      fetchJson("/api/incidents"),
    ]);
    capabilities = capabilityResult;
    incidents = incidentResult.incidents;
    setApiStatus(true, "API connected");
    renderIncidentList();
    if (currentIncident) {
      const stillListed = incidents.some(
        (item) => item.incident_id === currentIncident.incident_id,
      );
      if (stillListed) await loadIncident(currentIncident.incident_id);
      else {
        currentIncident = null;
        incidentNavigation.forEach((button) => {
          button.disabled = true;
        });
        selectedIncident.hidden = true;
        welcome.hidden = false;
      }
    }
  } catch (error) {
    setApiStatus(false, "API unavailable");
    incidentNavigation.forEach((button) => {
      button.disabled = true;
    });
    incidentList.replaceChildren();
    emptyInbox.hidden = false;
    emptyInbox.textContent = error.message;
  } finally {
    refreshButton.disabled = false;
  }
}

document.getElementById("approve-button").addEventListener("click", () => {
  if (!currentIncident?.remediation) return;
  const remediation = currentIncident.remediation;
  document.getElementById("approval-command").textContent =
    `You are approving: ${remediation.command}`;
  document.getElementById("replicas-field").hidden = remediation.action !== "scale";
  document.getElementById("confirm-input").checked = false;
  document.getElementById("token-input").value = "";
  approvalForm.hidden = false;
  approvalForm.scrollIntoView({ behavior: "smooth", block: "center" });
});

document.getElementById("copy-command").addEventListener("click", async () => {
  if (!currentIncident?.remediation?.command) return;
  try {
    await navigator.clipboard.writeText(currentIncident.remediation.command);
    actionResult.textContent = "Suggested command copied. It was not executed.";
  } catch (error) {
    actionResult.textContent = `Could not copy command: ${error.message}`;
  }
});

document.getElementById("cancel-approval").addEventListener("click", () => {
  approvalForm.reset();
  approvalForm.hidden = true;
});

approvalForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!currentIncident?.remediation || !capabilities.runbooks_available) return;
  const remediation = currentIncident.remediation;
  const payload = {
    approved: true,
    approver: document.getElementById("approver-input").value.trim(),
    service: currentIncident.service,
  };
  if (remediation.action === "scale") {
    payload.replicas = Number(document.getElementById("replicas-input").value);
  }

  const submitButton = approvalForm.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  actionResult.textContent = "Submitting explicitly approved action...";
  try {
    const result = await fetchJson(`/approvals/${encodeURIComponent(remediation.action)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Approval-Token": document.getElementById("token-input").value,
      },
      body: JSON.stringify(payload),
    });
    actionResult.textContent =
      `Action request completed: ${JSON.stringify(result)}. Verify rollout and SLO recovery separately.`;
    approvalForm.reset();
    approvalForm.hidden = true;
  } catch (error) {
    actionResult.textContent = `Action was not completed: ${error.message}`;
  } finally {
    submitButton.disabled = false;
  }
});

refreshButton.addEventListener("click", refreshDashboard);
incidentNavigation.forEach((button) => {
  button.addEventListener("click", () => navigateWithinIncident(button));
});
refreshDashboard();
