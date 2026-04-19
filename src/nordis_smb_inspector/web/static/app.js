"use strict";

const body = document.body;
const csrfToken = body.dataset.csrfToken;
const origin = body.dataset.origin;
const targets = document.querySelector("#targets");
const previewButton = document.querySelector("#preview-button");
const scopeState = document.querySelector("#scope-state");
const previewSummary = document.querySelector("#preview-summary");
const previewErrors = document.querySelector("#preview-errors");
const targetGroups = document.querySelector("#target-groups");
const rowCount = document.querySelector("#row-count");

function textCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value ?? "—";
  return cell;
}

function setScopeState(label, kind) {
  scopeState.textContent = label;
  scopeState.className = `state ${kind}`;
}

function showErrors(errors) {
  previewErrors.replaceChildren();
  for (const error of errors) {
    const line = document.createElement("p");
    line.textContent = `${error.value || "Girdi"}: ${error.reason}`;
    previewErrors.append(line);
  }
  previewErrors.hidden = errors.length === 0;
}

function groupStatus(group) {
  if (group.source_kind === "cidr") {
    return [`${group.candidate_count} aday hedef`, "ok-text"];
  }
  if (group.source_kind === "ip") return ["1 hedef", "ok-text"];
  if (group.failure_count > 0 && group.resolved_count > 0) return ["Kısmi", "warning-text"];
  if (group.failure_count > 0) return ["Çözümlenemedi", "error-text"];
  return [`${group.resolved_count} adres`, "ok-text"];
}

function groupHeader(group, elementName) {
  const header = document.createElement(elementName);
  header.className = "group-summary";
  const identity = document.createElement("span");
  identity.className = "group-identity";
  const source = document.createElement("code");
  source.textContent = group.source;
  const kind = document.createElement("span");
  kind.textContent = group.source_kind;
  identity.append(source, kind);

  const [statusLabel, statusClass] = groupStatus(group);
  const status = document.createElement("span");
  status.className = statusClass;
  status.textContent = statusLabel;
  header.append(identity, status);
  return header;
}

function renderGroups(groups) {
  targetGroups.replaceChildren();
  if (groups.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Hazırlanan hedef yok.";
    targetGroups.append(empty);
    return;
  }

  for (const group of groups) {
    if (group.details_hidden) {
      const compact = document.createElement("div");
      compact.className = "target-group compact-group";
      compact.append(groupHeader(group, "div"));
      targetGroups.append(compact);
      continue;
    }

    const details = document.createElement("details");
    details.className = "target-group";
    details.open = group.failure_count > 0;
    details.append(groupHeader(group, "summary"));

    const wrapper = document.createElement("div");
    wrapper.className = "group-table-wrap";
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");
    for (const label of ["Çözümlenen adres", "IP sürümü", "Durum"]) {
      const heading = document.createElement("th");
      heading.textContent = label;
      headRow.append(heading);
    }
    head.append(headRow);
    table.append(head);

    const body = document.createElement("tbody");
    for (const item of group.rows) {
      const row = document.createElement("tr");
      row.append(textCell(item.address ?? item.hostname));
      row.append(textCell(item.ip_version ? `IPv${item.ip_version}` : "—"));
      const rowStatus = textCell(
        item.status === "resolved" ? "Çözümlendi" : item.error_code,
      );
      rowStatus.className = item.status === "resolved" ? "ok-text" : "error-text";
      row.append(rowStatus);
      body.append(row);
    }
    table.append(body);
    wrapper.append(table);
    details.append(wrapper);
    targetGroups.append(details);
  }
}

async function previewScope() {
  previewButton.disabled = true;
  setScopeState("Hazırlanıyor", "working");
  previewSummary.textContent = "";
  showErrors([]);

  try {
    const response = await fetch("/scope/preview", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Origin": origin,
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({targets: targets.value}),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      const errors = payload.errors ?? [payload.error ?? {value: "İstek", reason: "Doğrulanamadı."}];
      showErrors(errors.map((item) => ({
        value: item.value ?? item.code,
        reason: item.reason ?? item.message,
      })));
      renderGroups([]);
      rowCount.textContent = "0 satır";
      setScopeState("Hatalı", "error");
      return;
    }

    renderGroups(payload.groups);
    const candidates = Number(payload.candidate_address_count).toLocaleString("tr-TR");
    rowCount.textContent = `${payload.groups.length} kaynak · ${candidates} aday hedef`;
    previewSummary.textContent = `${candidates} aday IP · ${payload.hostname_count} hostname`;
    if (payload.display_limited) {
      previewSummary.textContent += ` · DNS ayrıntıları ${payload.display_limit} satırla sınırlı`;
    }
    setScopeState("Hazır", "ready");
  } catch (_error) {
    showErrors([{value: "Bağlantı", reason: "Yerel panel yanıt vermedi."}]);
    setScopeState("Hata", "error");
  } finally {
    previewButton.disabled = false;
  }
}

async function refreshSnapshot() {
  try {
    const response = await fetch("/scan/snapshot", {cache: "no-store", credentials: "omit"});
    if (!response.ok) return;
    const state = await response.json();
    document.querySelector("#scan-status").textContent = state.status.toUpperCase();
    document.querySelector("#inventory-count").textContent = state.inventory_count;
    document.querySelector("#finding-count").textContent = state.finding_count;
    if (state.progress) {
      document.querySelector("#scan-phase").textContent = state.progress.phase.replaceAll("_", " ");
      const percent = state.progress.phase_percent;
      document.querySelector("#phase-percent").textContent = percent === null ? "—" : `${Math.round(percent)}%`;
      document.querySelector("#progress-bar").style.width = `${state.progress.overall_percent ?? percent ?? 0}%`;
      document.querySelector("#progress-message").textContent = state.progress.message ?? "Tarama çalışıyor.";
    }
  } catch (_error) {
    // Snapshot is best-effort; the page remains usable for scope editing.
  }
}

previewButton.addEventListener("click", previewScope);
refreshSnapshot();
