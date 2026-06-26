"use strict";

const CCACHE_MAX_BYTES = 1024 * 1024;
const ACTIVE_STATES = new Set(["running", "cancelling"]);

const controllerInput = document.querySelector("#ad-controller");
const domainInput = document.querySelector("#ad-domain");
const usernameInput = document.querySelector("#ad-username");
const usernameLabel = document.querySelector("#ad-username-label");
const credentialKind = document.querySelector("#ad-credential-kind");
const secretField = document.querySelector("#ad-secret-field");
const secretInput = document.querySelector("#ad-secret");
const secretLabel = document.querySelector("#ad-secret-label");
const ccacheField = document.querySelector("#ad-ccache-field");
const ccacheInput = document.querySelector("#ad-ccache");
const authMode = document.querySelector("#ad-auth-mode");
const kerberosHostnameField = document.querySelector("#ad-kerberos-hostname-field");
const kerberosHostnameInput = document.querySelector("#ad-kerberos-hostname");
const startButton = document.querySelector("#start-ad-scan");
const cancelButton = document.querySelector("#cancel-ad-scan");
const errors = document.querySelector("#ad-errors");
const statusBadge = document.querySelector("#ad-status-badge");
const phase = document.querySelector("#ad-phase");
const progressMessage = document.querySelector("#ad-progress-message");
const identityPanel = document.querySelector("#ad-identity-panel");
const identityPrincipal = document.querySelector("#ad-identity-principal");
const identityAuth = document.querySelector("#ad-identity-auth");
const identityGroups = document.querySelector("#ad-identity-groups");
const capabilityList = document.querySelector("#ad-capability-list");
const environmentList = document.querySelector("#ad-environment-list");
const computerBody = document.querySelector("#ad-computer-body");
const coverageList = document.querySelector("#ad-coverage-list");
const tabButtons = [...document.querySelectorAll("[data-ad-tab]")];
const tabPanels = [...document.querySelectorAll("[data-ad-panel]")];
const countElements = {
  capability: [
    document.querySelector("#ad-capability-count"),
    document.querySelector("#ad-capability-tab-count"),
  ],
  environment: [
    document.querySelector("#ad-environment-count"),
    document.querySelector("#ad-environment-tab-count"),
  ],
  computers: [
    document.querySelector("#ad-computer-count"),
    document.querySelector("#ad-computer-tab-count"),
  ],
  coverage: [document.querySelector("#ad-coverage-tab-count")],
};

let headersForMutation = null;
let pollTimer = null;
let renderedGeneration = null;
let renderedFindingCount = -1;
let renderedComputerCount = -1;

export function configureAdInspector({mutationHeaders}) {
  headersForMutation = mutationHeaders;
  credentialKind.addEventListener("change", syncCredentialControls);
  ccacheInput.addEventListener("change", validateCcache);
  authMode.addEventListener("change", syncKerberosHostname);
  startButton.addEventListener("click", startInspection);
  cancelButton.addEventListener("click", cancelInspection);
  for (const button of tabButtons) {
    button.addEventListener("click", () => activateTab(button.dataset.adTab));
  }
  syncCredentialControls();
  activateTab("capability");
}

export async function refreshAdInspector() {
  try {
    const response = await fetch("/ad/scan/snapshot", {cache: "no-store"});
    if (!response.ok) return;
    const snapshot = await response.json();
    renderSnapshot(snapshot);
    const generationChanged = renderedGeneration !== snapshot.generation;
    const resultsChanged = generationChanged
      || renderedFindingCount !== snapshot.finding_count
      || renderedComputerCount !== snapshot.computer_count;
    if (resultsChanged) {
      const [findings, computers] = await Promise.all([
        fetchAll("/ad/findings"),
        fetchAll("/ad/computers"),
      ]);
      renderFindings(findings);
      renderComputers(computers);
      renderedGeneration = snapshot.generation;
      renderedFindingCount = snapshot.finding_count;
      renderedComputerCount = snapshot.computer_count;
    }
    renderCoverage(snapshot.coverage ?? []);
    schedulePoll(ACTIVE_STATES.has(snapshot.status));
  } catch (_error) {
    schedulePoll(false);
  }
}

function syncCredentialControls() {
  const kind = credentialKind.value;
  const hashSelected = kind === "nt_hash";
  const ccacheSelected = kind === "ccache";
  usernameLabel.textContent = ccacheSelected ? "Kullanıcı (isteğe bağlı)" : "Kullanıcı";
  usernameInput.required = !ccacheSelected;
  secretLabel.textContent = hashSelected ? "NT hash" : "Parola";
  secretField.hidden = ccacheSelected;
  secretInput.disabled = ccacheSelected;
  secretInput.required = !ccacheSelected;
  ccacheField.hidden = !ccacheSelected;
  ccacheInput.disabled = !ccacheSelected;
  ccacheInput.required = ccacheSelected;
  ccacheInput.setCustomValidity("");
  if (!ccacheSelected) ccacheInput.value = "";
  if (hashSelected) {
    secretInput.pattern = "(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{32}:[0-9A-Fa-f]{32})";
    secretInput.maxLength = 65;
  } else {
    secretInput.removeAttribute("pattern");
    secretInput.removeAttribute("maxlength");
  }
  for (const option of authMode.options) {
    option.disabled = (hashSelected && option.value !== "ntlm_only")
      || (ccacheSelected && option.value !== "kerberos_only");
  }
  if (hashSelected) authMode.value = "ntlm_only";
  if (ccacheSelected) authMode.value = "kerberos_only";
  authMode.disabled = hashSelected || ccacheSelected;
  syncKerberosHostname();
}

function syncKerberosHostname() {
  const kerberosSelected = authMode.value === "kerberos_only";
  kerberosHostnameField.hidden = !kerberosSelected;
  kerberosHostnameInput.disabled = !kerberosSelected;
  if (!kerberosSelected) kerberosHostnameInput.value = "";
}

function validateCcache() {
  const file = ccacheInput.files?.[0];
  let message = "";
  if (credentialKind.value === "ccache") {
    if (!file) message = "CCache dosyası seçilmelidir.";
    else if (!file.name.toLocaleLowerCase("tr-TR").endsWith(".ccache")) {
      message = "Yalnız .ccache uzantılı dosya seçilebilir.";
    } else if (file.size === 0) message = "CCache dosyası boş olamaz.";
    else if (file.size > CCACHE_MAX_BYTES) message = "CCache dosyası en fazla 1 MiB olabilir.";
  }
  ccacheInput.setCustomValidity(message);
  return !message;
}

async function credentialPayload() {
  const kind = credentialKind.value;
  const domain = domainInput.value.trim();
  if (kind === "ccache") {
    if (!validateCcache()) throw new Error(ccacheInput.validationMessage);
    const file = ccacheInput.files[0];
    return {
      kind,
      auth_mode: "kerberos_only",
      domain,
      username: usernameInput.value.trim() || null,
      ccache_name: file.name,
      ccache_base64: arrayBufferToBase64(await file.arrayBuffer()),
    };
  }
  return {
    kind,
    auth_mode: authMode.value,
    domain,
    username: usernameInput.value.trim(),
    [kind === "nt_hash" ? "nt_hash" : "password"]: secretInput.value,
  };
}

async function startInspection() {
  clearError();
  if (!controllerInput.reportValidity() || !domainInput.reportValidity()) return;
  if (!usernameInput.reportValidity() || !secretInput.reportValidity()) return;
  if (credentialKind.value === "ccache" && !validateCcache()) {
    ccacheInput.reportValidity();
    return;
  }
  startButton.disabled = true;
  try {
    const response = await fetch("/ad/scan", {
      method: "POST",
      headers: headersForMutation(),
      body: JSON.stringify({
        controller: controllerInput.value.trim(),
        domain: domainInput.value.trim(),
        kerberos_hostname: kerberosHostnameInput.value.trim() || null,
        credential: await credentialPayload(),
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(responseErrorMessage(payload, "İnceleme başlatılamadı."));
    secretInput.value = "";
    ccacheInput.value = "";
    renderedGeneration = null;
    renderedFindingCount = -1;
    renderedComputerCount = -1;
    await refreshAdInspector();
  } catch (error) {
    showError(error instanceof Error ? error.message : "İnceleme başlatılamadı.");
    startButton.disabled = false;
  }
}

async function cancelInspection() {
  cancelButton.disabled = true;
  try {
    const response = await fetch("/ad/scan/cancel", {
      method: "POST",
      headers: headersForMutation(),
      body: "{}",
    });
    if (!response.ok) throw new Error("İptal isteği gönderilemedi.");
    await refreshAdInspector();
  } catch (error) {
    showError(error instanceof Error ? error.message : "İptal isteği gönderilemedi.");
  }
}

function renderSnapshot(snapshot) {
  const active = ACTIVE_STATES.has(snapshot.status);
  startButton.disabled = active;
  cancelButton.disabled = !active || snapshot.status === "cancelling";
  const labels = {
    idle: ["Hazır", "İnceleme yok", "Henüz Active Directory incelemesi başlatılmadı."],
    running: ["Çalışıyor", "LDAP kontrolleri çalışıyor", snapshot.progress?.message],
    cancelling: ["Durduruluyor", "İnceleme durduruluyor", "Devam eden LDAP sorgusunun bitmesi bekleniyor."],
    cancelled: ["İptal", "İnceleme iptal edildi", "Tamamlanan sonuçlar bellekte tutuluyor."],
    completed: ["Tamamlandı", "İnceleme tamamlandı", "Sonuçlar bağlı kimliğin görünürlüğünü yansıtır."],
    failed: ["Hata", "İnceleme tamamlanamadı", snapshot.terminal_error?.message],
  };
  const [badge, heading, message] = labels[snapshot.status] ?? labels.failed;
  statusBadge.textContent = badge;
  statusBadge.className = `state ${active ? "working" : snapshot.status === "completed" ? "ready" : snapshot.status === "failed" ? "error" : "idle"}`;
  phase.textContent = heading;
  progressMessage.textContent = message || "Durum bilgisi alınamadı.";
  const identity = snapshot.identity;
  identityPanel.hidden = !identity;
  if (identity) {
    identityPrincipal.textContent = identity.principal;
    identityAuth.textContent = snapshot.authentication_method === "kerberos" ? "Kerberos" : "NTLM";
    identityGroups.textContent = String(identity.groups?.length ?? 0);
  }
}

function renderFindings(findings) {
  const capabilities = findings.filter((item) => item.lane === "capability");
  const environment = findings.filter((item) => item.lane === "environment");
  renderFindingLane(capabilityList, capabilities, "Bu kimlikle kullanılabilir bir yol görülmedi.");
  renderFindingLane(environmentList, environment, "Görünen ortam zayıflığı yok.");
  setCount("capability", capabilities.length);
  setCount("environment", environment.length);
}

function renderFindingLane(container, findings, emptyMessage) {
  container.replaceChildren();
  if (!findings.length) {
    container.append(emptyState(emptyMessage));
    return;
  }
  for (const finding of findings) {
    const card = element("article", `ad-finding-card severity-${finding.severity}`);
    const header = element("header", "ad-finding-header");
    const heading = document.createElement("div");
    heading.append(element("h3", "", finding.title));
    if (finding.subject) heading.append(element("code", "ad-finding-subject", finding.subject));
    header.append(heading, statePill(finding.evidence_state));
    card.append(header, element("p", "ad-finding-summary", finding.summary));
    if (finding.evidence?.length) {
      const evidence = element("ul", "ad-evidence-list");
      for (const line of finding.evidence) evidence.append(element("li", "", line));
      card.append(evidence);
    }
    if (finding.next_step) {
      const next = element("p", "ad-next-step");
      next.append(element("span", "", "Sonraki adım"), document.createTextNode(finding.next_step));
      card.append(next);
    }
    container.append(card);
  }
}

function renderComputers(computers) {
  computerBody.replaceChildren();
  if (!computers.length) {
    const row = element("tr", "table-empty-row");
    const cell = element("td", "", "Görünen bilgisayar nesnesi yok.");
    cell.colSpan = 4;
    row.append(cell);
    computerBody.append(row);
  } else {
    for (const computer of computers) {
      const row = document.createElement("tr");
      row.append(
        element("td", "code-value", computer.hostname || "—"),
        element("td", "code-value", computer.account_name),
        element("td", "", computer.operating_system || "—"),
        element("td", "", computer.enabled ? "Etkin" : "Devre dışı"),
      );
      computerBody.append(row);
    }
  }
  setCount("computers", computers.length);
}

function renderCoverage(coverage) {
  coverageList.replaceChildren();
  if (!coverage.length) {
    coverageList.append(emptyState("Henüz kontrol çalıştırılmadı."));
    setCount("coverage", 0);
    return;
  }
  for (const item of coverage) {
    const row = element("div", "ad-coverage-row");
    const copy = document.createElement("div");
    copy.append(element("strong", "", item.label));
    const detail = item.message || `${item.records_seen} kayıt değerlendirildi.`;
    copy.append(element("span", "", detail));
    row.append(copy, coveragePill(item.state));
    coverageList.append(row);
  }
  setCount("coverage", coverage.length);
}

function statePill(state) {
  const labels = {verified: "Doğrulandı", inferred: "Çıkarım", observed: "Gözlem"};
  return element("span", `ad-state-pill ${state}`, labels[state] || state);
}

function coveragePill(state) {
  const labels = {completed: "Tamamlandı", partial: "Kısmi", not_checked: "Kontrol edilmedi"};
  return element("span", `ad-coverage-state ${state}`, labels[state] || state);
}

function activateTab(name) {
  for (const button of tabButtons) {
    const active = button.dataset.adTab === name;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  }
  for (const panel of tabPanels) panel.hidden = panel.dataset.adPanel !== name;
}

async function fetchAll(endpoint) {
  const firstResponse = await fetch(`${endpoint}?page=1&page_size=1000`, {cache: "no-store"});
  if (!firstResponse.ok) return [];
  const first = await firstResponse.json();
  const items = [...first.items];
  for (let page = 2; page <= first.total_pages; page += 1) {
    const response = await fetch(`${endpoint}?page=${page}&page_size=1000`, {cache: "no-store"});
    if (!response.ok) break;
    items.push(...(await response.json()).items);
  }
  return items;
}

function schedulePoll(active) {
  if (pollTimer !== null) window.clearTimeout(pollTimer);
  pollTimer = active ? window.setTimeout(refreshAdInspector, 750) : null;
}

function setCount(name, value) {
  for (const target of countElements[name]) target.textContent = String(value);
}

function showError(message) {
  errors.replaceChildren(element("p", "", message));
  errors.hidden = false;
}

function responseErrorMessage(payload, fallback) {
  if (typeof payload?.error === "string" && payload.error) return payload.error;
  if (typeof payload?.error?.message === "string" && payload.error.message) {
    return payload.error.message;
  }
  const first = Array.isArray(payload?.errors) ? payload.errors[0] : null;
  if (typeof first?.reason === "string" && first.reason) return first.reason;
  return fallback;
}

function clearError() {
  errors.replaceChildren();
  errors.hidden = true;
}

function emptyState(message) {
  return element("p", "group-empty-state", message);
}

function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== "") node.textContent = text;
  return node;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 16 * 1024) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 16 * 1024));
  }
  return btoa(binary);
}
