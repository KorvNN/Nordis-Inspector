"use strict";

const body = document.body;
const csrfToken = body.dataset.csrfToken;
const origin = body.dataset.origin;
const targets = document.querySelector("#targets");
const previewButton = document.querySelector("#preview-button");
const scopeState = document.querySelector("#scope-state");
const previewSummary = document.querySelector("#preview-summary");
const previewErrors = document.querySelector("#preview-errors");
const targetRows = document.querySelector("#target-rows");
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

function renderRows(rows) {
  targetRows.replaceChildren();
  if (rows.length === 0) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = textCell("Çözümlenen hedef yok.");
    cell.colSpan = 4;
    row.append(cell);
    targetRows.append(row);
    return;
  }

  for (const item of rows) {
    const row = document.createElement("tr");
    row.append(textCell(item.source));
    row.append(textCell(item.address ?? item.hostname));
    row.append(textCell(item.source_kind ?? "hostname"));
    const status = textCell(item.status === "resolved" ? "Çözümlendi" : item.error_code);
    status.className = item.status === "resolved" ? "ok-text" : "error-text";
    row.append(status);
    targetRows.append(row);
  }
}

async function previewScope() {
  previewButton.disabled = true;
  setScopeState("Çözümleniyor", "working");
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
      renderRows([]);
      rowCount.textContent = "0 satır";
      setScopeState("Hatalı", "error");
      return;
    }

    renderRows(payload.rows);
    rowCount.textContent = `${payload.rows.length} satır`;
    const known = Number(payload.known_address_count).toLocaleString("tr-TR");
    previewSummary.textContent = `${known} bilinen adres · ${payload.hostname_count} hostname`;
    if (payload.display_limited) {
      previewSummary.textContent += ` · İlk ${payload.display_limit} satır gösteriliyor`;
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
