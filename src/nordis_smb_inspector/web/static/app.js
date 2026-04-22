"use strict";

const body = document.body;
const csrfToken = body.dataset.csrfToken;
const origin = body.dataset.origin;
const targets = document.querySelector("#targets");
const credentialDomain = document.querySelector("#credential-domain");
const credentialUsername = document.querySelector("#credential-username");
const credentialKind = document.querySelector("#credential-kind");
const credentialSecret = document.querySelector("#credential-secret");
const credentialSecretLabel = document.querySelector("#credential-secret-label");
const authMode = document.querySelector("#auth-mode");
const useDefaultWordlist = document.querySelector("#use-default-wordlist");
const additionalTermsInput = document.querySelector("#additional-terms");
const maxDepthInput = document.querySelector("#max-depth");
const startScanButton = document.querySelector("#start-scan-button");
const cancelScanButton = document.querySelector("#cancel-scan-button");
const scopeState = document.querySelector("#scope-state");
const previewErrors = document.querySelector("#preview-errors");
const scanPhase = document.querySelector("#scan-phase");
const targetStatusBody = document.querySelector("#target-status-body");
const visibleTargetCount = document.querySelector("#visible-target-count");
const targetFilters = [...document.querySelectorAll("[data-target-filter]")];
const targetCountElements = [...document.querySelectorAll("[data-target-count]")];
const inventoryBody = document.querySelector("#inventory-body");
const inventoryFilter = document.querySelector("#inventory-filter");
const inventoryVisibleCount = document.querySelector("#inventory-visible-count");
const findingsBody = document.querySelector("#findings-body");
const findingsFilter = document.querySelector("#findings-filter");
const findingsVisibleCount = document.querySelector("#findings-visible-count");
const targetStore = new Map();
const inventoryStore = new Map();
const findingStore = new Map();
let selectedTargetFilter = "all";
let latestGeneration = null;

const ATTENTION_STATUS = /(?:DENIED|FAILED|ERROR|REFUSED|TIMEOUT|UNREACHABLE|UNAVAILABLE|VIOLATION)/u;
const WORKING_STATUS = /(?:PENDING|CONNECTING|NEGOTIATING|AUTHENTICATING|SCANNING|RUNNING)/u;
const OK_STATUS = /(?:OPEN|READY|SUCCESS|AUTHENTICATED|COMPLETED|PARTIAL_ACCESS)/u;
const STATUS_LABELS = {
  port_open: "445 açık",
  timeout_no_response: "Yanıt yok / timeout",
  connection_refused: "Bağlantı reddedildi",
  network_unreachable: "Ağa ulaşılamıyor",
  connection_error: "Bağlantı hatası",
  dns_resolution_failed: "DNS çözümlenemedi",
  negotiation_failed: "SMB görüşmesi başarısız",
  smb1_only_unsupported: "Yalnız SMB1 destekleniyor",
  authenticated: "Doğrulandı",
  kerberos: "Kerberos",
  ntlm: "NTLM",
  ntlm_fallback_used: "NTLM fallback kullanıldı",
  auth_failed: "Kimlik doğrulanamadı",
  ntlm_fallback_unavailable: "NTLM fallback kullanılamıyor",
  access_denied: "Erişim reddedildi",
  partial_access: "Kısmi erişim",
  cancelled: "İptal edildi",
  completed: "Tamamlandı",
  failed: "Başarısız",
};
const SCAN_STATUS_LABELS = {
  idle: "Tarama yok",
  running: "Çalışıyor",
  cancelling: "İptal ediliyor",
  cancelled: "İptal edildi",
  completed: "Tamamlandı",
  failed: "Başarısız",
};
const PHASE_LABELS = {
  preparing_targets: "Hedefler hazırlanıyor",
  connectivity: "TCP/445 kontrolü",
  authentication: "Kimlik doğrulama",
  share_discovery: "Share keşfi",
  file_inventory: "Dosya envanteri",
  content_scan: "İçerik taraması",
  cancelling: "İptal ediliyor",
  cancelled: "İptal edildi",
  completed: "Tamamlandı",
  failed: "Başarısız",
};
const STATUS_MESSAGES = {
  idle: "Yeni bir tarama başlatılmadı.",
  cancelling: "Tarama iptal ediliyor.",
  cancelled: "Tarama iptal edildi.",
  completed: "Tarama tamamlandı.",
  failed: "Tarama başarısız.",
};
const MESSAGE_LABELS = {
  "Cancellation requested.": "İptal isteği gönderildi.",
  "Scan cancelled.": "Tarama iptal edildi.",
  "Scan worker failed.": "Tarama başarısız.",
};

function textCell(value, className = "") {
  const cell = document.createElement("td");
  const display = document.createElement("span");
  display.className = className;
  display.textContent = displayValue(value);
  cell.append(display);
  return cell;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  const raw = String(value);
  return STATUS_LABELS[raw.toLowerCase()] ?? raw;
}

function firstValue(record, names) {
  for (const name of names) {
    const value = record?.[name];
    if (value !== null && value !== undefined && value !== "") return value;
  }
  return null;
}

function nestedRecord(payload, names) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  for (const name of names) {
    const candidate = payload[name];
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      return candidate;
    }
  }
  return payload;
}

function resultArray(payload, names) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return null;
  for (const name of ["items", ...names]) {
    if (Array.isArray(payload[name])) return payload[name];
  }
  return null;
}

function normalizedSearch(value) {
  return displayValue(value).toLocaleLowerCase("tr-TR");
}

function recordMatchesSearch(record, query, fields) {
  const needle = query.trim().toLocaleLowerCase("tr-TR");
  if (!needle) return true;
  return fields.some((field) => normalizedSearch(record[field]).includes(needle));
}

function formatSize(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `${value.toLocaleString("tr-TR")} B`;
  }
  return value;
}

function normalizedStatus(value) {
  if (value === null || value === undefined || value === "") return "";
  return String(value).trim().toUpperCase().replaceAll(" ", "_");
}

function statusTone(value) {
  const status = normalizedStatus(value);
  if (ATTENTION_STATUS.test(status)) return "is-error";
  if (WORKING_STATUS.test(status)) return "is-working";
  if (OK_STATUS.test(status)) return "is-ok";
  return "";
}

function targetRecord(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const candidate = payload.target && typeof payload.target === "object"
    ? payload.target
    : payload;
  const ip = firstValue(candidate, ["ip", "address", "target_address", "target"]);
  if (typeof ip !== "string" || ip.trim() === "") return null;

  return {
    ip: ip.trim(),
    tcp: firstValue(candidate, ["tcp_status", "tcp_445_status", "connectivity_status"]),
    smb: firstValue(candidate, ["smb_status", "negotiation_status", "smb_dialect"]),
    authentication: firstValue(candidate, [
      "authentication_status",
      "auth_status",
      "authentication_method",
      "auth_method",
    ]),
    lastStatus: firstValue(candidate, ["last_status", "final_status", "status", "last_stage"]),
  };
}

function targetMatches(record, filter) {
  if (filter === "all") return true;
  const tcp = normalizedStatus(record.tcp);
  const smb = normalizedStatus(record.smb);
  const authentication = normalizedStatus(record.authentication);
  const combined = [tcp, smb, authentication, normalizedStatus(record.lastStatus)].join(" ");

  if (filter === "tcp_open") return /(?:PORT_)?OPEN/u.test(tcp);
  if (filter === "smb_ready") {
    return /(?:NEGOTIATED|READY|SUCCESS|SMB(?:2|3)|2\.\d|3\.\d)/u.test(smb);
  }
  if (filter === "authenticated") {
    return /(?:AUTHENTICATED|SUCCESS|KERBEROS|NTLM)/u.test(authentication)
      && !ATTENTION_STATUS.test(authentication);
  }
  if (filter === "attention") return ATTENTION_STATUS.test(combined);
  return true;
}

function updateTargetCounters() {
  const records = [...targetStore.values()];
  for (const element of targetCountElements) {
    const filter = element.dataset.targetCount;
    const count = records.filter((record) => targetMatches(record, filter)).length;
    element.textContent = count.toLocaleString("tr-TR");
  }
}

function setTargetTableMessage(message) {
  const row = document.createElement("tr");
  row.className = "table-empty-row";
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = message;
  row.append(cell);
  targetStatusBody.replaceChildren(row);
  visibleTargetCount.textContent = "0 hedef";
}

function renderTargetRows(emptyMessage = "Henüz tarama başlatılmadı.") {
  const records = [...targetStore.values()];
  targetStatusBody.replaceChildren();

  let visible = 0;
  for (const record of records) {
    if (!targetMatches(record, selectedTargetFilter)) continue;
    const row = document.createElement("tr");
    row.dataset.targetIp = record.ip;
    row.append(textCell(record.ip));
    row.append(textCell(record.tcp, `status-value ${statusTone(record.tcp)}`));
    row.append(textCell(record.smb, `status-value ${statusTone(record.smb)}`));
    row.append(textCell(
      record.authentication,
      `status-value ${statusTone(record.authentication)}`,
    ));
    row.append(textCell(record.lastStatus, `status-value ${statusTone(record.lastStatus)}`));
    targetStatusBody.append(row);
    visible += 1;
  }

  if (visible === 0) {
    const message = records.length > 0
      ? "Bu filtreyle eşleşen hedef yok."
      : emptyMessage;
    setTargetTableMessage(message);
  } else {
    visibleTargetCount.textContent = `${visible.toLocaleString("tr-TR")} hedef`;
  }
  updateTargetCounters();
}

function upsertTarget(payload) {
  const record = targetRecord(payload);
  if (!record) return false;
  const previous = targetStore.get(record.ip) ?? {};
  const changes = Object.fromEntries(
    Object.entries(record).filter(([, value]) => value !== null),
  );
  targetStore.set(record.ip, {...previous, ...changes});
  renderTargetRows("Hedef durumları bekleniyor.");
  return true;
}

function replaceTargets(records) {
  if (!Array.isArray(records)) return false;
  targetStore.clear();
  for (const item of records) {
    const record = targetRecord(item);
    if (record) targetStore.set(record.ip, record);
  }
  renderTargetRows("Hedef durumları bekleniyor.");
  return true;
}

function inventoryRecord(payload) {
  const candidate = nestedRecord(payload, ["inventory", "item", "record"]);
  if (!candidate) return null;
  const target = firstValue(candidate, ["target", "ip", "address", "hostname"]);
  const share = firstValue(candidate, ["share", "share_name"]);
  const path = firstValue(candidate, [
    "path",
    "relative_path",
    "unc_path",
    "file_path",
    "directory_path",
  ]);
  if (target === null && share === null && path === null) return null;
  return {
    id: firstValue(candidate, ["id", "record_id", "inventory_id"]),
    target,
    share,
    path,
    type: firstValue(candidate, ["type", "item_type", "kind", "entry_type"]),
    status: firstValue(candidate, ["status", "read_status", "content_status", "scan_status"]),
    size: firstValue(candidate, ["size", "size_bytes", "file_size"]),
  };
}

function inventoryKey(record) {
  if (record.id !== null) return `id:${String(record.id)}`;
  return [record.target, record.share, record.path, record.type]
    .map((value) => displayValue(value))
    .join("\u001f");
}

function findingRecord(payload) {
  const candidate = nestedRecord(payload, ["finding", "item", "record"]);
  if (!candidate) return null;
  const file = firstValue(candidate, ["file", "filename", "file_path", "unc_path", "path"]);
  const lineNumber = firstValue(candidate, ["line_number", "line_no", "line_index"]);
  const term = firstValue(candidate, ["term", "matched_term", "search_term", "rule_id"]);
  let fullLine = firstValue(candidate, [
    "full_line",
    "matched_line",
    "line_text",
    "context",
    "text",
    "value",
  ]);
  if (fullLine === null && typeof candidate.line === "string") fullLine = candidate.line;
  if (file === null && term === null && fullLine === null) return null;
  return {
    id: firstValue(candidate, ["id", "finding_id", "record_id"]),
    target: firstValue(candidate, ["target", "ip", "address", "hostname"]),
    share: firstValue(candidate, ["share", "share_name"]),
    file,
    lineNumber,
    term,
    fullLine,
  };
}

function findingKey(record) {
  if (record.id !== null) return `id:${String(record.id)}`;
  return [record.target, record.share, record.file, record.lineNumber, record.term]
    .map((value) => displayValue(value))
    .join("\u001f");
}

function setResultTableMessage(bodyElement, colspan, message) {
  const row = document.createElement("tr");
  row.className = "table-empty-row";
  const cell = document.createElement("td");
  cell.colSpan = colspan;
  cell.textContent = message;
  row.append(cell);
  bodyElement.replaceChildren(row);
}

function renderInventory() {
  inventoryBody.replaceChildren();
  let visible = 0;
  for (const record of inventoryStore.values()) {
    if (!recordMatchesSearch(
      record,
      inventoryFilter.value,
      ["target", "share", "path", "type", "status", "size"],
    )) continue;
    const row = document.createElement("tr");
    row.append(textCell(record.target));
    row.append(textCell(record.share));
    row.append(textCell(record.path, "path-value"));
    row.append(textCell(record.type));
    row.append(textCell(record.status, `status-value ${statusTone(record.status)}`));
    row.append(textCell(formatSize(record.size)));
    inventoryBody.append(row);
    visible += 1;
  }
  if (inventoryStore.size === 0) {
    setResultTableMessage(inventoryBody, 6, "Henüz envanter yok.");
  }
  inventoryVisibleCount.textContent = `${visible.toLocaleString("tr-TR")} kayıt`;
}

function renderFindings() {
  findingsBody.replaceChildren();
  let visible = 0;
  for (const record of findingStore.values()) {
    if (!recordMatchesSearch(
      record,
      findingsFilter.value,
      ["target", "share", "file", "lineNumber", "term", "fullLine"],
    )) continue;
    const row = document.createElement("tr");
    row.append(textCell(record.file, "path-value"));
    row.append(textCell(record.lineNumber));
    row.append(textCell(record.term));
    row.append(textCell(record.fullLine, "finding-line"));
    findingsBody.append(row);
    visible += 1;
  }
  if (findingStore.size === 0) {
    setResultTableMessage(findingsBody, 4, "Henüz bulgu yok.");
  }
  findingsVisibleCount.textContent = `${visible.toLocaleString("tr-TR")} bulgu`;
}

function upsertInventory(payload) {
  const record = inventoryRecord(payload);
  if (!record) return false;
  inventoryStore.set(inventoryKey(record), record);
  renderInventory();
  return true;
}

function upsertFinding(payload) {
  const record = findingRecord(payload);
  if (!record) return false;
  findingStore.set(findingKey(record), record);
  renderFindings();
  return true;
}

function replaceInventory(records) {
  if (!Array.isArray(records)) return false;
  inventoryStore.clear();
  for (const item of records) {
    const record = inventoryRecord(item);
    if (record) inventoryStore.set(inventoryKey(record), record);
  }
  renderInventory();
  return true;
}

function replaceFindings(records) {
  if (!Array.isArray(records)) return false;
  findingStore.clear();
  for (const item of records) {
    const record = findingRecord(item);
    if (record) findingStore.set(findingKey(record), record);
  }
  renderFindings();
  return true;
}

function clearResults() {
  inventoryStore.clear();
  findingStore.clear();
  renderInventory();
  renderFindings();
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

function syncCredentialControls() {
  const hashSelected = credentialKind.value === "nt_hash";
  credentialSecretLabel.textContent = hashSelected ? "NT hash" : "Parola";
  credentialSecret.value = "";
  if (hashSelected) {
    credentialSecret.setAttribute(
      "pattern",
      "(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32})",
    );
    credentialSecret.setAttribute("maxlength", "65");
  } else {
    credentialSecret.removeAttribute("pattern");
    credentialSecret.removeAttribute("maxlength");
  }

  for (const option of authMode.options) {
    option.disabled = hashSelected && option.value !== "ntlm_only";
  }
  authMode.value = hashSelected ? "ntlm_only" : "auto";
  authMode.disabled = hashSelected;
}

function credentialPayload() {
  const kind = credentialKind.value;
  const secretField = kind === "nt_hash" ? "nt_hash" : "password";
  return {
    kind,
    domain: credentialDomain.value.trim() || null,
    username: credentialUsername.value.trim(),
    auth_mode: authMode.value,
    [secretField]: credentialSecret.value,
  };
}

function credentialIsValid() {
  return credentialUsername.reportValidity() && credentialSecret.reportValidity();
}

function additionalSearchTerms() {
  const terms = additionalTermsInput.value
    .split(/[\n,]+/u)
    .map((term) => term.trim())
    .filter(Boolean);
  return [...new Set(terms)];
}

function scanFormIsValid() {
  return credentialIsValid() && maxDepthInput.reportValidity();
}

async function startScan() {
  if (!scanFormIsValid()) return;
  startScanButton.disabled = true;
  setScopeState("Başlatılıyor", "working");
  showErrors([]);

  try {
    const response = await fetch("/scan", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Origin": origin,
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({
        targets: targets.value,
        credential: credentialPayload(),
        search: {
          use_default: useDefaultWordlist.checked,
          additional_terms: additionalSearchTerms(),
        },
        max_depth: Number(maxDepthInput.value),
      }),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      const errors = payload.errors ?? [payload.error ?? {value: "İstek", reason: "Doğrulanamadı."}];
      showErrors(errors.map((item) => ({
        value: item.value ?? item.code,
        reason: item.reason ?? item.message,
      })));
      setScopeState("Hatalı", "error");
      return;
    }

    targetStore.clear();
    renderTargetRows("Hedef sonuçları bekleniyor.");
    clearResults();
    setScopeState("Çalışıyor", "working");
    cancelScanButton.disabled = false;
    await refreshSnapshot();
  } catch (_error) {
    showErrors([{value: "Bağlantı", reason: "Yerel panel yanıt vermedi."}]);
    setScopeState("Hata", "error");
  } finally {
    if (cancelScanButton.disabled) startScanButton.disabled = false;
  }
}

async function cancelScan() {
  cancelScanButton.disabled = true;
  try {
    const response = await fetch("/scan/cancel", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Origin": origin,
        "X-CSRF-Token": csrfToken,
      },
      body: "{}",
    });
    if (response.ok) {
      setScopeState("İptal ediliyor", "working");
    }
  } catch (_error) {
    showErrors([{value: "İptal", reason: "Yerel panel yanıt vermedi."}]);
  }
}

function setScanState(state) {
  const status = String(state.status ?? "idle").toLowerCase();
  const phase = String(state.progress?.phase ?? "").toLowerCase();
  const terminal = ["completed", "cancelled", "failed"].includes(status);
  scanPhase.textContent = terminal
    ? SCAN_STATUS_LABELS[status]
    : PHASE_LABELS[phase] ?? SCAN_STATUS_LABELS[status] ?? "Bilinmiyor";

  if (state.progress) {
    const percent = state.progress.phase_percent;
    const displayedPercent = status === "completed" ? 100 : percent;
    document.querySelector("#phase-percent").textContent = displayedPercent === null
      ? "—"
      : `${Math.round(displayedPercent)}%`;
    const overallPercent = status === "completed"
      ? 100
      : state.progress.overall_percent ?? percent ?? 0;
    document.querySelector("#progress-bar").style.width = `${overallPercent}%`;
  }
  if (!state.progress) {
    document.querySelector("#phase-percent").textContent = "—";
    document.querySelector("#progress-bar").style.width = "0%";
  }
  const rawMessage = state.progress?.message;
  document.querySelector("#progress-message").textContent = terminal
    ? STATUS_MESSAGES[status]
    : rawMessage
      ? MESSAGE_LABELS[rawMessage] ?? rawMessage
      : STATUS_MESSAGES[status] ?? "";

  document.querySelector("#inventory-count").textContent = state.inventory_count ?? 0;
  document.querySelector("#finding-count").textContent = state.finding_count ?? 0;
  const active = ["running", "cancelling"].includes(status);
  startScanButton.disabled = active;
  cancelScanButton.disabled = !active || status === "cancelling";
  if (!active && status !== "idle") {
    const kind = status === "failed" ? "error" : "ready";
    setScopeState(SCAN_STATUS_LABELS[status] ?? "Bitti", kind);
  }
}

function targetsFromSnapshot(state) {
  const records = state.targets ?? state.target_statuses;
  if (Array.isArray(records)) replaceTargets(records);
}

function resultsFromSnapshot(state) {
  const inventory = resultArray(state, ["inventory", "inventory_items"]);
  const findings = resultArray(state, ["findings", "finding_items"]);
  if (inventory) replaceInventory(inventory);
  if (findings) replaceFindings(findings);
}

async function fetchResultArray(path, names) {
  const response = await fetch(path, {cache: "no-store", credentials: "omit"});
  if (!response.ok) return null;
  return resultArray(await response.json(), names);
}

async function refreshResultPanels() {
  try {
    const [inventory, findings] = await Promise.all([
      fetchResultArray("/inventory", ["inventory", "inventory_items"]),
      fetchResultArray("/findings", ["findings", "finding_items"]),
    ]);
    if (inventory) replaceInventory(inventory);
    if (findings) replaceFindings(findings);
  } catch (_error) {
    // Live events and the next snapshot can still update these RAM-only views.
  }
}

async function refreshSnapshot() {
  try {
    const response = await fetch("/scan/snapshot", {cache: "no-store", credentials: "omit"});
    if (!response.ok) return;
    const state = await response.json();
    if (latestGeneration !== null && state.generation !== latestGeneration) {
      targetStore.clear();
      clearResults();
    }
    latestGeneration = state.generation;
    setScanState(state);
    targetsFromSnapshot(state);
    resultsFromSnapshot(state);
    if (targetStore.size === 0) {
      const message = state.status === "idle"
        ? "Henüz tarama başlatılmadı."
        : "Hedef durumları bekleniyor.";
      renderTargetRows(message);
    }
  } catch (_error) {
    // Snapshot is best-effort; the page remains usable for scope editing.
  }
}

function handleServerEvent(event) {
  try {
    const payload = JSON.parse(event.data);
    if (event.type === "target.changed") upsertTarget(payload);
    if (event.type === "inventory.added") upsertInventory(payload);
    if (event.type === "finding.added") upsertFinding(payload);
    if (event.type === "snapshot") {
      setScanState(payload);
      targetsFromSnapshot(payload);
      resultsFromSnapshot(payload);
    }
  } catch (_error) {
    // Invalid or incomplete live events are ignored; the snapshot remains authoritative.
  }
}

for (const filter of targetFilters) {
  filter.addEventListener("click", () => {
    selectedTargetFilter = filter.dataset.targetFilter;
    for (const item of targetFilters) {
      const active = item === filter;
      item.classList.toggle("is-active", active);
      item.setAttribute("aria-pressed", String(active));
    }
    renderTargetRows(targetStore.size === 0
      ? "Henüz tarama başlatılmadı."
      : "Bu filtreyle eşleşen hedef yok.");
  });
}

startScanButton.addEventListener("click", startScan);
cancelScanButton.addEventListener("click", cancelScan);
credentialKind.addEventListener("change", syncCredentialControls);
inventoryFilter.addEventListener("input", renderInventory);
findingsFilter.addEventListener("input", renderFindings);
syncCredentialControls();
refreshSnapshot();
refreshResultPanels();

const scanEvents = new EventSource("/scan/events");
for (const eventName of [
  "target.changed",
  "inventory.added",
  "finding.added",
  "snapshot",
]) {
  scanEvents.addEventListener(eventName, handleServerEvent);
}
scanEvents.addEventListener("resync.required", async () => {
  await refreshSnapshot();
  await refreshResultPanels();
});
