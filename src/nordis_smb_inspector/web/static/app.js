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
const startScanButton = document.querySelector("#start-scan-button");
const cancelScanButton = document.querySelector("#cancel-scan-button");
const scopeState = document.querySelector("#scope-state");
const previewSummary = document.querySelector("#preview-summary");
const previewErrors = document.querySelector("#preview-errors");
const scanPhase = document.querySelector("#scan-phase");
const targetStatusBody = document.querySelector("#target-status-body");
const visibleTargetCount = document.querySelector("#visible-target-count");
const targetFilters = [...document.querySelectorAll("[data-target-filter]")];
const targetCountElements = [...document.querySelectorAll("[data-target-count]")];
const targetStore = new Map();
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
  running: "İşlem sürüyor.",
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

async function startScan() {
  if (!credentialIsValid()) return;
  startScanButton.disabled = true;
  setScopeState("Başlatılıyor", "working");
  previewSummary.textContent = "";
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
      }),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      const errors = payload.errors ?? [payload.error ?? {value: "İstek", reason: "Doğrulanamadı."}];
      showErrors(errors.map((item) => ({
        value: item.value ?? item.code,
        reason: item.reason ?? item.message,
      })));
      previewSummary.textContent = "Tarama başlatılamadı.";
      setScopeState("Hatalı", "error");
      return;
    }

    targetStore.clear();
    renderTargetRows("Hedef sonuçları bekleniyor.");
    previewSummary.textContent = "Adres aralığı taranıyor; yanıt verenler aşağıda görünecek.";
    setScopeState("Çalışıyor", "working");
    cancelScanButton.disabled = false;
    await refreshSnapshot();
  } catch (_error) {
    showErrors([{value: "Bağlantı", reason: "Yerel panel yanıt vermedi."}]);
    previewSummary.textContent = "Tarama başlatılamadı.";
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
      previewSummary.textContent = "Tarama iptal isteği gönderildi.";
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
      : STATUS_MESSAGES[status] ?? "Durum bilgisi alınamadı.";

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

async function refreshSnapshot() {
  try {
    const response = await fetch("/scan/snapshot", {cache: "no-store", credentials: "omit"});
    if (!response.ok) return;
    const state = await response.json();
    if (latestGeneration !== null && state.generation !== latestGeneration) {
      targetStore.clear();
    }
    latestGeneration = state.generation;
    setScanState(state);
    targetsFromSnapshot(state);
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
    if (event.type === "snapshot") {
      setScanState(payload);
      targetsFromSnapshot(payload);
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
syncCredentialControls();
refreshSnapshot();

const scanEvents = new EventSource("/scan/events");
for (const eventName of ["target.changed", "snapshot"]) {
  scanEvents.addEventListener(eventName, handleServerEvent);
}
scanEvents.addEventListener("resync.required", refreshSnapshot);
