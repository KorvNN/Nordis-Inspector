"use strict";

import {
  configureHashTools,
  hashToolErrorMessage,
  refreshHashTools,
  renderHashCandidates,
  sendFindingToHashTools,
  setHashScanActive,
} from "./app-hash-tools.js";
import {
  configureHistory,
  renderHistory,
  setSelectedHistoryKey,
  storedHistory,
  writeHistory,
} from "./app-history.js";
import {
  EN_CATEGORY_LABELS,
  EN_FINDING_METHOD_LABELS,
  EN_FINDING_RULE_LABELS,
  EN_HASH_FORMAT_LABELS,
  EN_HASH_JOB_LABELS,
  EN_PHASE_LABELS,
  EN_SCAN_STATUS_LABELS,
  EN_STATUS_LABELS,
  EN_STATUS_MESSAGES,
  ERROR_MESSAGE_LABELS,
  FINDING_METHOD_LABELS,
  FINDING_RULE_LABELS,
  HASH_FORMAT_LABELS,
  HASH_JOB_LABELS,
  LANGUAGE_KEY,
  MESSAGE_LABELS,
  PHASE_LABELS,
  SCAN_STATUS_LABELS,
  STATUS_LABELS,
  STATUS_MESSAGES,
  TR_CATEGORY_LABELS,
  applyLanguage,
  currentLanguage,
  localizedMap,
  numberLocale,
  uiText,
} from "./app-i18n.js";

const body = document.body;
const languageSelect = document.querySelector("#language-select");
const workspaceNavigationItems = [...document.querySelectorAll("[data-workspace-view]")];
const scanWorkspace = document.querySelector("#scan-workspace");
const hashToolsWorkspace = document.querySelector("#hash-tools-workspace");
const csrfToken = body.dataset.csrfToken;
const origin = body.dataset.origin;
const targets = document.querySelector("#targets");
const scanName = document.querySelector("#scan-name");
const credentialDomain = document.querySelector("#credential-domain");
const credentialUsername = document.querySelector("#credential-username");
const credentialUsernameLabel = document.querySelector("#credential-username-label");
const credentialKind = document.querySelector("#credential-kind");
const credentialSecretField = document.querySelector("#credential-secret-field");
const credentialSecret = document.querySelector("#credential-secret");
const credentialSecretLabel = document.querySelector("#credential-secret-label");
const credentialCcacheField = document.querySelector("#credential-ccache-field");
const credentialCcache = document.querySelector("#credential-ccache");
const authMode = document.querySelector("#auth-mode");
const additionalTermsInput = document.querySelector("#additional-terms");
const additionalTermsFile = document.querySelector("#additional-terms-file");
const additionalTermsStatus = document.querySelector("#additional-terms-status");
const toggleTermGenerator = document.querySelector("#toggle-term-generator");
const termGenerator = document.querySelector("#term-generator");
const termGeneratorRoots = document.querySelector("#term-generator-roots");
const generateCredentialTerms = document.querySelector("#generate-credential-terms");
const generateEnvironmentTerms = document.querySelector("#generate-environment-terms");
const generateTermsButton = document.querySelector("#generate-terms");
const termGeneratorStatus = document.querySelector("#term-generator-status");
const detectPatternsInput = document.querySelector("#detect-patterns");
const testWriteAccessInput = document.querySelector("#test-write-access");
const rulePackSelector = document.querySelector("#rule-pack-selector");
const rulePackCount = document.querySelector("#rule-pack-count");
const patternRulePackInputs = [...document.querySelectorAll("[data-rule-pack]")];
const startScanButton = document.querySelector("#start-scan-button");
const cancelScanButton = document.querySelector("#cancel-scan-button");
const previewErrors = document.querySelector("#preview-errors");
const scanPhase = document.querySelector("#scan-phase");
const targetStatusBody = document.querySelector("#target-status-body");
const visibleTargetCount = document.querySelector("#visible-target-count");
const targetFilters = [...document.querySelectorAll("[data-target-filter]")];
const targetCountElements = [...document.querySelectorAll("[data-target-count]")];
const inventoryGroups = document.querySelector("#inventory-groups");
const inventoryFilter = document.querySelector("#inventory-filter");
const inventoryVisibleCount = document.querySelector("#inventory-visible-count");
const findingsGroups = document.querySelector("#findings-groups");
const findingsFilter = document.querySelector("#findings-filter");
const findingsVisibleCount = document.querySelector("#findings-visible-count");
const resultTabs = [...document.querySelectorAll("[data-result-tab]")];
const resultPanels = [...document.querySelectorAll("[data-result-panel]")];
const targetWorkspaceCount = document.querySelector("[data-workspace-count='targets']");
const inventoryTabCount = document.querySelector("#inventory-tab-count");
const findingsTabCount = document.querySelector("#findings-tab-count");
const exportResultsButton = document.querySelector("#export-results");
const targetSelectionDetail = document.querySelector("#target-selection-detail");
const inventorySelectionDetail = document.querySelector("#inventory-selection-detail");
const findingSelectionDetail = document.querySelector("#finding-selection-detail");
const targetStore = new Map();
const inventoryStore = new Map();
const findingStore = new Map();
const inventoryGroupOpenState = new Map();
const findingGroupOpenState = new Map();
let selectedTargetFilter = "all";
let selectedTargetKey = null;
let selectedInventoryKey = null;
let selectedFindingKey = null;
let latestGeneration = null;
let pendingScanInputs = null;
const scanInputSnapshots = new Map();

const CCACHE_MAX_BYTES = 1024 * 1024;
const CUSTOM_TERMS_MAX_BYTES = 1024 * 1024;
const MAX_GENERATED_TERMS = 2000;
const GENERATOR_CREDENTIAL_FIELDS = [
  "password",
  "secret",
  "token",
  "api key",
  "access token",
  "client secret",
  "private key",
  "connection string",
];
const GENERATOR_ENVIRONMENTS = ["dev", "test", "staging", "prod", "production"];
const DETECTION_RULE_PACK_LABELS = {
  general_secrets: "Genel sırlar ve tokenlar",
  windows_ad: "Windows ve Active Directory",
  password_hashes: "Parola hashleri",
  cloud_services: "Bulut ve kaynak kod servisleri",
  infrastructure: "Altyapı ve geliştirici araçları",
};
class CredentialInputError extends Error {}

const ATTENTION_STATUS = /(?:DENIED|FAILED|ERROR|REFUSED|TIMEOUT|UNREACHABLE|UNAVAILABLE|VIOLATION)/u;
const WORKING_STATUS = /(?:PENDING|CONNECTING|NEGOTIATING|AUTHENTICATING|SCANNING|RUNNING)/u;
const OK_STATUS = /(?:OPEN|READY|SUCCESS|ALLOWED|AUTHENTICATED|DOĞRULANDI|KERBEROS|NTLM|COMPLETED|PARTIAL_ACCESS|CONNECTED|LISTABLE|READABLE)/u;

function textCell(value, className = "") {
  const cell = document.createElement("td");
  const display = document.createElement("span");
  display.className = className;
  display.textContent = displayValue(value);
  cell.append(display);
  return cell;
}

function setSelectionPlaceholder(container, message) {
  const placeholder = document.createElement("p");
  placeholder.className = "selection-placeholder";
  placeholder.textContent = uiText(message);
  container.replaceChildren(placeholder);
}

function detailList(fields) {
  const list = document.createElement("dl");
  list.className = "detail-list";
  for (const [label, value, className = ""] of fields) {
    const group = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = uiText(label);
    description.className = className;
    description.textContent = displayValue(value);
    group.append(term, description);
    list.append(group);
  }
  return list;
}

function renderSelectionDetail(container, title, fields) {
  const heading = document.createElement("h3");
  heading.className = "detail-heading";
  heading.textContent = displayValue(title);

  const list = detailList(fields);
  container.replaceChildren(heading, list);
}

function appendHighlightedText(container, value, term) {
  const text = displayValue(value);
  const needle = term === null || term === undefined ? "" : String(term).trim();
  if (needle === "") {
    container.textContent = text;
    return;
  }

  const searchableText = text.toLocaleLowerCase("tr-TR");
  const searchableNeedle = needle.toLocaleLowerCase("tr-TR");
  let cursor = 0;
  let matchIndex = searchableText.indexOf(searchableNeedle);
  if (matchIndex === -1) {
    container.textContent = text;
    return;
  }

  while (matchIndex !== -1) {
    container.append(document.createTextNode(text.slice(cursor, matchIndex)));
    const highlight = document.createElement("mark");
    highlight.textContent = text.slice(matchIndex, matchIndex + needle.length);
    container.append(highlight);
    cursor = matchIndex + needle.length;
    matchIndex = searchableText.indexOf(searchableNeedle, cursor);
  }
  container.append(document.createTextNode(text.slice(cursor)));
}

function bindSelectableRow(row, {selected, select}) {
  row.tabIndex = 0;
  row.classList.toggle("is-selected", selected);
  row.setAttribute("aria-selected", String(selected));
  row.addEventListener("click", select);
  row.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    select();
  });
}

function activateResultTab(name) {
  for (const tab of resultTabs) {
    const active = tab.dataset.resultTab === name;
    tab.classList.toggle("is-active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  }
  for (const panel of resultPanels) {
    panel.hidden = panel.dataset.resultPanel !== name;
  }
}

function activateWorkspace(name) {
  const hashToolsActive = name === "hash-tools";
  scanWorkspace.hidden = hashToolsActive;
  hashToolsWorkspace.hidden = !hashToolsActive;
  for (const item of workspaceNavigationItems) {
    const active = item.dataset.workspaceView === name;
    item.classList.toggle("is-active", active);
    item.setAttribute("aria-pressed", String(active));
  }
  if (hashToolsActive) {
    renderHashCandidates();
    void refreshHashTools();
  }
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  const raw = String(value);
  return localizedMap(STATUS_LABELS, EN_STATUS_LABELS, raw.toLowerCase()) ?? raw;
}

function writeAccessLabel(value) {
  return String(value).toLowerCase() === "unknown" ? uiText("Test edilmedi") : displayValue(value);
}

function findingLabel(value, labels) {
  if (value === null || value === undefined || value === "") return "—";
  const raw = String(value);
  if (currentLanguage === "en") {
    const english = labels === FINDING_METHOD_LABELS
      ? EN_FINDING_METHOD_LABELS
      : EN_FINDING_RULE_LABELS;
    return english[raw.toLowerCase()] ?? labels[raw.toLowerCase()] ?? raw;
  }
  return labels[raw.toLowerCase()] ?? raw;
}

function categoryLabel(value) {
  if (value === null || value === undefined || value === "") return "—";
  const raw = String(value);
  const labels = currentLanguage === "en" ? EN_CATEGORY_LABELS : TR_CATEGORY_LABELS;
  return labels[raw] ?? raw;
}

function hashFormatLabel(value) {
  if (value === null || value === undefined || value === "") return "—";
  const key = String(value);
  const labels = currentLanguage === "en" ? EN_HASH_FORMAT_LABELS : HASH_FORMAT_LABELS;
  return labels[key] ?? key;
}

function hashJobLabel(value) {
  const key = value === null || value === undefined ? "idle" : String(value);
  const labels = currentLanguage === "en" ? EN_HASH_JOB_LABELS : HASH_JOB_LABELS;
  return labels[key] ?? key;
}

function confidenceLabel(value) {
  const level = displayValue(value);
  const explanations = currentLanguage === "en"
    ? {
        High: "Strong · A specific credential format was found.",
        Medium: "Review needed · A general key/value pattern was found.",
        Low: "Weak · This may be a false positive.",
      }
    : {
        Yüksek: "Güçlü · Belirgin bir kimlik bilgisi biçimi bulundu.",
        Orta: "İnceleme gerekli · Genel bir anahtar/değer kalıbı bulundu.",
        Düşük: "Zayıf · Yanlış eşleşme olabilir.",
      };
  return explanations[level] ?? level;
}

function findingAssignmentKey(record) {
  if (String(record.ruleId).toLowerCase() !== "secret-assignment") return null;
  const line = record.fullLine === null || record.fullLine === undefined
    ? ""
    : String(record.fullLine);
  const match = line.match(
    /\b(api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|pwd|secret|token)[ \t]*[:=]/iu,
  );
  return match?.[1] ?? null;
}

function isPatternFinding(record) {
  return String(record.method).toLowerCase() === "pattern";
}

function isArtifactFinding(record) {
  return String(record.method).toLowerCase() === "artifact";
}

function isStructuredFinding(record) {
  return isPatternFinding(record) || isArtifactFinding(record);
}

function findingSignalValue(record) {
  if (isStructuredFinding(record) && FINDING_RULE_LABELS[record.ruleId]) {
    return findingLabel(record.ruleId, FINDING_RULE_LABELS);
  }
  return displayValue(record.term);
}

function findingHighlightTerm(record) {
  return findingAssignmentKey(record) ?? (isStructuredFinding(record) ? null : record.term);
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
  return displayValue(value).toLocaleLowerCase(numberLocale());
}

function recordMatchesSearch(record, query, fields) {
  const needle = query.trim().toLocaleLowerCase(numberLocale());
  if (!needle) return true;
  return fields.some((field) => normalizedSearch(record[field]).includes(needle));
}

function formatSize(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return `${value.toLocaleString(numberLocale())} B`;
  }
  return value;
}

function formatFileSize(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB"];
  let amount = value;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  const digits = unitIndex === 0 || amount >= 100 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toLocaleString(numberLocale(), {maximumFractionDigits: digits})} ${units[unitIndex]}`;
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
    tcp: firstValue(candidate, ["tcp", "tcp_status", "tcp_445_status", "connectivity_status"]),
    smb: firstValue(candidate, ["smb", "smb_status", "negotiation_status", "smb_dialect"]),
    signing: firstValue(candidate, ["signing"]) ?? securityFeatureValue(candidate, "signing"),
    encryption: firstValue(candidate, ["encryption"])
      ?? securityFeatureValue(candidate, "encryption"),
    authentication: targetAuthenticationValue(candidate),
    lastStatus: firstValue(candidate, ["lastStatus", "last_status", "final_status", "status", "last_stage"]),
    detail: firstValue(candidate, ["detail"])
      ?? targetErrorDetail(candidate) ?? targetErrorDetail(payload),
    sharesProbed: firstValue(candidate, ["sharesProbed", "shares_probed"]),
    sharesAccessible: firstValue(candidate, ["sharesAccessible", "shares_accessible"]),
    filesSeen: firstValue(candidate, ["filesSeen", "files_seen"]),
    filesScanned: firstValue(candidate, ["filesScanned", "files_scanned"]),
    unreadableFiles: firstValue(candidate, ["unreadableFiles", "unreadable_files"]),
    errorName: firstValue(candidate, ["errorName", "error_name"]),
    rawErrorCode: firstValue(candidate, ["rawErrorCode", "raw_error_code"]),
    errorMessage: firstValue(candidate, ["errorMessage", "error_message"]),
  };
}

function renderTargetDetail(record) {
  renderSelectionDetail(targetSelectionDetail, record.ip, [
    ["TCP/445", record.tcp],
    ["SMB sürümü", record.smb],
    ["İmzalama", record.signing],
    ["Şifreleme", record.encryption],
    ["Kimlik doğrulama", record.authentication],
    ["Son durum", record.lastStatus],
    ["Denenen share", record.sharesProbed],
    ["Erişilen share", record.sharesAccessible],
    ["Görülen dosya", record.filesSeen],
    ["Taranan dosya", record.filesScanned],
    ["Okunamayan dosya", record.unreadableFiles],
    ["Hata ayrıntısı", targetErrorDetail(record) ?? record.detail],
  ]);
}

function targetAuthenticationValue(record) {
  const normalized = firstValue(record, ["authentication"]);
  if (normalized !== null) {
    return currentLanguage === "en"
      ? String(normalized).replace(/^Doğrulandı/u, "Authenticated")
      : String(normalized).replace(/^Authenticated/u, "Doğrulandı");
  }
  const method = firstValue(record, ["authentication_method", "auth_method"]);
  if (method !== null) return `${currentLanguage === "en" ? "Authenticated" : "Doğrulandı"} · ${displayValue(method)}`;
  return firstValue(record, ["authentication_status", "auth_status"]);
}

function targetErrorDetail(record) {
  const errorName = firstValue(record, ["errorName", "error_name"]);
  const rawCode = firstValue(record, ["rawErrorCode", "raw_error_code"]);
  const errorMessage = firstValue(record, ["errorMessage", "error_message"]);
  const values = [
    errorName === null ? null : displayValue(errorName),
    rawCode === null ? null : `${currentLanguage === "en" ? "Code" : "Kod"} ${rawCode}`,
    errorMessage === null
      ? null
      : currentLanguage === "tr"
        ? ERROR_MESSAGE_LABELS[String(errorMessage)] ?? String(errorMessage)
        : String(errorMessage),
  ].filter((value) => value !== null && value !== undefined && value !== "");
  return [...new Set(values)].join(" · ") || null;
}

function securityFeatureValue(record, prefix) {
  const active = record?.[`${prefix}_active`];
  const required = record?.[`${prefix}_required`];
  const supported = record?.[`${prefix}_supported`];
  if (active === true && required === true) return "security_active_required";
  if (active === true) return "security_active";
  if (required === true) return "security_required";
  if (supported === true) return "security_supported";
  if (supported === false) return "security_unsupported";
  return null;
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
  targetWorkspaceCount.textContent = records.length.toLocaleString(numberLocale());
  for (const element of targetCountElements) {
    const filter = element.dataset.targetCount;
    const count = records.filter((record) => targetMatches(record, filter)).length;
    element.textContent = count.toLocaleString(numberLocale());
  }
}

function setTargetTableMessage(message) {
  const row = document.createElement("tr");
  row.className = "table-empty-row";
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.textContent = uiText(message);
  row.append(cell);
  targetStatusBody.replaceChildren(row);
  visibleTargetCount.textContent = currentLanguage === "en" ? "0 targets" : "0 hedef";
}

function renderTargetRows(emptyMessage = "Henüz tarama başlatılmadı.") {
  const records = [...targetStore.values()];
  const visibleRecords = records.filter((record) => targetMatches(record, selectedTargetFilter));
  if (!visibleRecords.some((record) => record.ip === selectedTargetKey)) {
    selectedTargetKey = visibleRecords[0]?.ip ?? null;
    if (visibleRecords[0]) renderTargetDetail(visibleRecords[0]);
    else setSelectionPlaceholder(targetSelectionDetail, "Ayrıntı için bir hedef seç.");
  }
  targetStatusBody.replaceChildren();

  let visible = 0;
  for (const record of visibleRecords) {
    const row = document.createElement("tr");
    row.append(textCell(record.ip, "code-value"));
    row.append(textCell(record.tcp, `status-value ${statusTone(record.tcp)}`));
    row.append(textCell(record.smb, `status-value ${statusTone(record.smb)}`));
    row.append(textCell(
      record.authentication,
      `status-value ${statusTone(record.authentication)}`,
    ));
    row.append(textCell(record.lastStatus, `status-value ${statusTone(record.lastStatus)}`));
    bindSelectableRow(row, {
      selected: selectedTargetKey === record.ip,
      select: () => {
        selectedTargetKey = record.ip;
        renderTargetRows(emptyMessage);
        renderTargetDetail(record);
      },
    });
    targetStatusBody.append(row);
    visible += 1;
  }

  if (visible === 0) {
    const message = records.length > 0
      ? "Bu filtreyle eşleşen hedef yok."
      : emptyMessage;
    setTargetTableMessage(message);
  } else {
    visibleTargetCount.textContent = currentLanguage === "en"
      ? `${visible.toLocaleString(numberLocale())} targets`
      : `${visible.toLocaleString(numberLocale())} hedef`;
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
  if (selectedTargetKey === record.ip) {
    renderTargetDetail(targetStore.get(record.ip));
  }
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
  if (selectedTargetKey !== null && !targetStore.has(selectedTargetKey)) {
    selectedTargetKey = null;
    setSelectionPlaceholder(targetSelectionDetail, "Ayrıntı için bir hedef seç.");
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
    readAccess: firstValue(candidate, ["readAccess", "read_access"]),
    writeAccess: firstValue(candidate, ["writeAccess", "write_access"]),
    size: firstValue(candidate, ["size", "size_bytes", "file_size"]),
    modifiedAt: firstValue(candidate, ["modifiedAt", "modified_at", "modified", "mtime"]),
    detail: firstValue(candidate, ["detail"]) ?? targetErrorDetail(candidate),
    errorName: firstValue(candidate, ["errorName", "error_name"]),
    rawErrorCode: firstValue(candidate, ["rawErrorCode", "raw_error_code"]),
    errorMessage: firstValue(candidate, ["errorMessage", "error_message"]),
  };
}

function inventoryKey(record) {
  if (record.id !== null) return `id:${String(record.id)}`;
  return [record.target, record.share, record.path, record.type]
    .map((value) => displayValue(value))
    .join("\u001f");
}

function renderInventoryDetail(record) {
  renderSelectionDetail(inventorySelectionDetail, record.path || record.share, [
    ["Hedef", record.target],
    ["Share", record.share],
    ["Path", record.path],
    ["Tür", record.type],
    ["Durum", record.status],
    ["Okuma", record.readAccess],
    ["Yazma", writeAccessLabel(record.writeAccess)],
    ["Boyut", formatSize(record.size)],
    ["Değiştirilme", record.modifiedAt],
    ["Hata ayrıntısı", targetErrorDetail(record) ?? record.detail],
  ]);
}

function normalizedAuditCandidates(candidate) {
  const source = candidate?.auditCandidates ?? candidate?.audit_candidates;
  if (!Array.isArray(source)) return [];
  const candidates = [];
  for (const item of source) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    if (
      typeof item.id !== "string"
      || typeof item.variant !== "string"
      || typeof item.format !== "string"
    ) continue;
    const tools = Array.isArray(item.tools)
      ? item.tools
        .filter((tool) => (
          tool
          && typeof tool === "object"
          && !Array.isArray(tool)
          && typeof tool.id === "string"
          && typeof tool.format === "string"
        ))
        .map((tool) => ({id: tool.id, format: tool.format}))
      : [];
    if (tools.length === 0) continue;
    candidates.push({id: item.id, variant: item.variant, format: item.format, tools});
  }
  return candidates;
}

function findingRecord(payload) {
  const candidate = nestedRecord(payload, ["finding", "item", "record"]);
  if (!candidate) return null;
  const file = firstValue(candidate, ["file", "filename", "file_path", "unc_path", "path"]);
  const lineNumber = firstValue(candidate, ["lineNumber", "line_number", "line_no", "line_index"]);
  const term = firstValue(candidate, ["term", "matched_term", "search_term", "rule_id"]);
  let fullLine = firstValue(candidate, [
    "fullLine",
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
    method: firstValue(candidate, ["method", "detection_method"]),
    ruleId: firstValue(candidate, ["ruleId", "rule_id", "rule"]),
    category: firstValue(candidate, ["category", "rule_category"]),
    confidence: firstValue(candidate, ["confidence", "confidence_level"]),
    auditCandidates: normalizedAuditCandidates(candidate),
  };
}

function findingKey(record) {
  if (record.id !== null) return `id:${String(record.id)}`;
  return [
    record.target,
    record.share,
    record.file,
    record.lineNumber,
    record.method,
    record.ruleId,
    record.term,
  ]
    .map((value) => displayValue(value))
    .join("\u001f");
}

function renderFindingDetail(record) {
  const header = document.createElement("header");
  header.className = "finding-detail-header";
  const heading = document.createElement("h3");
  heading.className = "detail-heading";
  heading.textContent = displayValue(record.file);
  header.append(heading);
  if (record.auditCandidates.length > 0) {
    const forward = document.createElement("button");
    forward.type = "button";
    forward.className = "secondary-button finding-hash-action";
    forward.textContent = uiText("Hash Araçlarına gönder");
    forward.addEventListener("click", () => sendFindingToHashTools(record));
    header.append(forward);
  }

  const detailSections = [header];
  if (!isArtifactFinding(record)) {
    const context = document.createElement("section");
    context.className = "finding-context";
    const contextLabel = document.createElement("span");
    contextLabel.className = "finding-context-label";
    contextLabel.textContent = uiText("Satır içeriği");
    const line = document.createElement("code");
    appendHighlightedText(line, record.fullLine, findingHighlightTerm(record));
    context.append(contextLabel, line);
    detailSections.push(context);
  }
  if (isStructuredFinding(record)) {
    const signal = document.createElement("section");
    signal.className = "finding-signal";
    const signalLabel = document.createElement("span");
    signalLabel.className = "finding-signal-label";
    signalLabel.textContent = uiText("Bulgu");
    const signalValue = document.createElement("strong");
    signalValue.className = "finding-signal-value";
    signalValue.textContent = findingSignalValue(record);
    signal.append(signalLabel, signalValue);
    detailSections.push(signal);
  }

  const metadataFields = [
    ["Hedef", record.target, "detail-code"],
    ["Share", record.share, "detail-code"],
  ];
  if (record.lineNumber !== null && record.lineNumber !== undefined) {
    metadataFields.push(["Satır no", record.lineNumber, "detail-code"]);
  }
  metadataFields.push(["Kaynak", findingLabel(record.method, FINDING_METHOD_LABELS)]);
  if (isStructuredFinding(record)) {
    metadataFields.push(
      ["Bulgu sınıfı", categoryLabel(record.category)],
      ["Eşleşme gücü", confidenceLabel(record.confidence)],
    );
  }
  const metadata = detailList(metadataFields);
  metadata.classList.add("finding-metadata");
  findingSelectionDetail.replaceChildren(...detailSections, metadata);
}

function recordsByTarget(records) {
  const groups = new Map();
  for (const item of records) {
    const target = item[1].target === null ? "Hedef bilinmiyor" : String(item[1].target);
    if (!groups.has(target)) groups.set(target, []);
    groups.get(target).push(item);
  }
  return groups;
}

function inventorySections(records) {
  const sections = new Map();
  for (const item of records) {
    const target = item[1].target === null ? "Hedef bilinmiyor" : String(item[1].target);
    const share = item[1].share === null ? "Share bilinmiyor" : String(item[1].share);
    if (!sections.has(target)) sections.set(target, new Map());
    const shares = sections.get(target);
    if (!shares.has(share)) shares.set(share, new Map());
    const kinds = shares.get(share);
    const kind = item[1].type ?? "other";
    if (!kinds.has(kind)) kinds.set(kind, []);
    kinds.get(kind).push(item);
  }
  return sections;
}

function inventoryKindLabel(kind) {
  const labels = currentLanguage === "en"
    ? {share: "Share", directory: "Directories", file: "Files", other: "Other"}
    : {share: "Share", directory: "Dizinler", file: "Dosyalar", other: "Diğer"};
  return labels[kind] ?? String(kind);
}

function inventoryShareStatusLabel(status) {
  const labels = currentLanguage === "en"
    ? {
      share_connected: "Accessible",
      share_access_denied: "Access denied",
      non_file_share: "Non-file share",
    }
    : {
      share_connected: "Erişilebilir",
      share_access_denied: "Erişim reddedildi",
      non_file_share: "Dosya paylaşımı değil",
    };
  return labels[String(status).toLowerCase()] ?? displayValue(status);
}

function orderedInventoryKinds(kinds) {
  const order = new Map(["share", "directory", "file", "other"].map((kind, index) => [kind, index]));
  return [...kinds].sort(([left], [right]) => {
    const leftIndex = order.get(left) ?? order.size;
    const rightIndex = order.get(right) ?? order.size;
    return leftIndex - rightIndex || String(left).localeCompare(String(right), currentLanguage);
  });
}

function nestedInventoryCount(groups) {
  let count = 0;
  for (const records of groups.values()) count += records.length;
  return count;
}

function setGroupedResultMessage(container, message) {
  const emptyState = document.createElement("p");
  emptyState.className = "group-empty-state";
  emptyState.textContent = message;
  container.replaceChildren(emptyState);
}

function groupedResult({
  target,
  records,
  openState,
  defaultOpen,
  stateKey = target,
  extraClass = "",
  countLabel,
  tableClass,
  headings,
  rowForRecord,
}) {
  const details = document.createElement("details");
  details.className = `result-group${extraClass ? ` ${extraClass}` : ""}`;
  details.dataset.groupTarget = target;
  details.open = openState.has(stateKey) ? openState.get(stateKey) : defaultOpen;
  details.addEventListener("toggle", () => openState.set(stateKey, details.open));

  const summary = document.createElement("summary");
  const targetLabel = document.createElement("span");
  targetLabel.className = "result-group-target";
  targetLabel.textContent = target;
  const count = document.createElement("span");
  count.className = "result-group-count";
  count.textContent = `${records.length.toLocaleString(numberLocale())} ${uiText(countLabel)}`;
  summary.append(targetLabel, count);

  const frame = resultTable({records, tableClass, headings, rowForRecord});
  details.append(summary, frame);
  return details;
}

function resultTable({records, tableClass, headings, rowForRecord}) {
  const frame = document.createElement("div");
  frame.className = "group-table-frame";
  const table = document.createElement("table");
  table.className = `result-table ${tableClass}`;
  const head = document.createElement("thead");
  const headingRow = document.createElement("tr");
  for (const heading of headings) {
    const cell = document.createElement("th");
    cell.scope = "col";
    cell.textContent = uiText(heading);
    headingRow.append(cell);
  }
  head.append(headingRow);
  const bodyElement = document.createElement("tbody");
  for (const item of records) bodyElement.append(rowForRecord(item));
  table.append(head, bodyElement);
  frame.append(table);
  return frame;
}

function inventoryTable(kinds) {
  const contentKinds = orderedInventoryKinds(kinds).filter(([kind]) => kind !== "share");
  if (contentKinds.length === 0) return null;

  const frame = document.createElement("div");
  frame.className = "group-table-frame";
  const table = document.createElement("table");
  table.className = "result-table inventory-table";
  const columns = document.createElement("colgroup");
  for (const className of ["inventory-path-column", "inventory-status-column"]) {
    const column = document.createElement("col");
    column.className = className;
    columns.append(column);
  }
  table.append(columns);

  for (const [kind, records] of contentKinds) {
    const body = document.createElement("tbody");
    body.className = "inventory-kind-section";
    const kindRow = document.createElement("tr");
    kindRow.className = "inventory-kind-heading-row";
    const kindCell = document.createElement("th");
    kindCell.colSpan = 2;
    kindCell.textContent = inventoryKindLabel(kind);
    kindRow.append(kindCell);
    body.append(kindRow);

    for (const [key, record] of records) {
      const row = document.createElement("tr");
      row.append(textCell(record.path || record.share, "path-value"));
      row.append(textCell(record.status, `status-value ${statusTone(record.status)}`));
      bindSelectableRow(row, {
        selected: selectedInventoryKey === key,
        select: () => {
          selectedInventoryKey = key;
          renderInventory();
          renderInventoryDetail(record);
        },
      });
      body.append(row);
    }
    table.append(body);
  }
  frame.append(table);
  return frame;
}

function renderInventory() {
  const visibleRecords = [...inventoryStore].filter(([, record]) => recordMatchesSearch(
    record,
    inventoryFilter.value,
    ["target", "share", "path", "type", "status", "readAccess", "writeAccess", "size", "detail"],
  ));
  if (!visibleRecords.some(([key]) => key === selectedInventoryKey)) {
    selectedInventoryKey = visibleRecords[0]?.[0] ?? null;
    if (visibleRecords[0]) renderInventoryDetail(visibleRecords[0][1]);
    else setSelectionPlaceholder(inventorySelectionDetail, "Ayrıntı için bir kayıt seç.");
  }
  const groups = inventorySections(visibleRecords);
  const allGroups = inventorySections([...inventoryStore]);
  inventoryGroups.replaceChildren();
  let groupIndex = 0;
  for (const [target, shares] of groups) {
    const targetStateKey = `target:${target}`;
    const targetGroup = document.createElement("details");
    targetGroup.className = "result-group inventory-target-group";
    targetGroup.open = inventoryGroupOpenState.has(targetStateKey)
      ? inventoryGroupOpenState.get(targetStateKey)
      : groupIndex === 0;
    targetGroup.addEventListener("toggle", () => {
      inventoryGroupOpenState.set(targetStateKey, targetGroup.open);
    });
    const targetSummary = document.createElement("summary");
    const targetLabel = document.createElement("span");
    targetLabel.className = "result-group-target";
    targetLabel.textContent = target;
    const targetCount = document.createElement("span");
    targetCount.className = "result-group-count";
    const targetRecordCount = [...shares.values()]
      .reduce((total, kinds) => total + nestedInventoryCount(kinds), 0);
    targetCount.textContent = currentLanguage === "en"
      ? `${targetRecordCount} entries`
      : `${targetRecordCount} kayıt`;
    targetSummary.append(targetLabel, targetCount);
    targetGroup.append(targetSummary);
    let shareIndex = 0;
    for (const [share, kinds] of shares) {
      const shareStateKey = `share:${target}\u001f${share}`;
      const shareGroup = document.createElement("details");
      shareGroup.className = "result-group inventory-share-group";
      shareGroup.open = inventoryGroupOpenState.has(shareStateKey)
        ? inventoryGroupOpenState.get(shareStateKey)
        : shareIndex === 0;
      shareGroup.addEventListener("toggle", () => {
        inventoryGroupOpenState.set(shareStateKey, shareGroup.open);
      });
      const shareSummary = document.createElement("summary");
      const shareLabel = document.createElement("span");
      shareLabel.className = "result-group-target";
      shareLabel.textContent = share;
      const shareItem = allGroups.get(target)?.get(share)?.get("share")?.[0] ?? null;
      const shareStatus = document.createElement("span");
      const shareStatusValue = shareItem?.[1].status ?? "unknown";
      shareStatus.className = `status-value result-group-status ${statusTone(shareStatusValue)}`;
      shareStatus.textContent = inventoryShareStatusLabel(shareStatusValue);
      shareSummary.append(shareLabel, shareStatus);
      const writeAccess = shareItem?.[1].writeAccess;
      if (writeAccess && String(writeAccess).toLowerCase() !== "unknown") {
        const writeStatus = document.createElement("span");
        writeStatus.className = `status-value ${statusTone(writeAccess)}`;
        writeStatus.textContent = `${uiText("Yazma")}: ${displayValue(writeAccess)}`;
        shareSummary.append(writeStatus);
      }
      if (shareItem) {
        shareSummary.addEventListener("click", () => {
          selectedInventoryKey = shareItem[0];
          for (const row of inventoryGroups.querySelectorAll("tr.is-selected")) {
            row.classList.remove("is-selected");
          }
          renderInventoryDetail(shareItem[1]);
        });
      }
      shareGroup.append(shareSummary);
      const contentTable = inventoryTable(kinds);
      if (contentTable) {
        shareGroup.append(contentTable);
      } else {
        shareGroup.classList.add("is-empty");
        shareSummary.addEventListener("click", (event) => event.preventDefault());
      }
      targetGroup.append(shareGroup);
      shareIndex += 1;
    }
    inventoryGroups.append(targetGroup);
    groupIndex += 1;
  }
  if (visibleRecords.length === 0) {
    setGroupedResultMessage(
      inventoryGroups,
      inventoryStore.size === 0 ? "Henüz envanter yok." : "Filtreyle eşleşen kayıt yok.",
    );
  }
  inventoryVisibleCount.textContent = currentLanguage === "en"
    ? `${visibleRecords.length.toLocaleString(numberLocale())} entries`
    : `${visibleRecords.length.toLocaleString(numberLocale())} kayıt`;
  inventoryTabCount.textContent = inventoryStore.size.toLocaleString(numberLocale());
}

function renderFindings() {
  const visibleRecords = [...findingStore].filter(([, record]) => recordMatchesSearch(
    record,
    findingsFilter.value,
    [
      "target",
      "share",
      "file",
      "lineNumber",
      "term",
      "fullLine",
      "method",
      "ruleId",
      "category",
      "confidence",
    ],
  ));
  if (!visibleRecords.some(([key]) => key === selectedFindingKey)) {
    selectedFindingKey = visibleRecords[0]?.[0] ?? null;
    if (visibleRecords[0]) renderFindingDetail(visibleRecords[0][1]);
    else setSelectionPlaceholder(findingSelectionDetail, "Ayrıntı için bir bulgu seç.");
  }
  const groups = recordsByTarget(visibleRecords);
  findingsGroups.replaceChildren();
  let groupIndex = 0;
  for (const [target, records] of groups) {
    findingsGroups.append(groupedResult({
      target,
      records,
      openState: findingGroupOpenState,
      defaultOpen: groupIndex === 0,
      countLabel: "bulgu",
      tableClass: "findings-table",
      headings: ["Dosya", "Satır no", "Kaynak", "Bulgu"],
      rowForRecord: ([key, record]) => {
        const row = document.createElement("tr");
        row.append(textCell(record.file, "path-value"));
        row.append(textCell(record.lineNumber, "code-value"));
        row.append(textCell(
          findingLabel(record.method, FINDING_METHOD_LABELS),
          `status-value ${statusTone(record.method)}`,
        ));
        row.append(textCell(findingSignalValue(record), "finding-term-pill"));
        bindSelectableRow(row, {
          selected: selectedFindingKey === key,
          select: () => {
            selectedFindingKey = key;
            renderFindings();
            renderFindingDetail(record);
          },
        });
        return row;
      },
    }));
    groupIndex += 1;
  }
  if (visibleRecords.length === 0) {
    setGroupedResultMessage(
      findingsGroups,
      findingStore.size === 0 ? "Henüz bulgu yok." : "Filtreyle eşleşen bulgu yok.",
    );
  }
  findingsVisibleCount.textContent = currentLanguage === "en"
    ? `${visibleRecords.length.toLocaleString(numberLocale())} findings`
    : `${visibleRecords.length.toLocaleString(numberLocale())} bulgu`;
  findingsTabCount.textContent = findingStore.size.toLocaleString(numberLocale());
  renderHashCandidates();
}


function upsertInventory(payload) {
  const record = inventoryRecord(payload);
  if (!record) return false;
  const key = inventoryKey(record);
  inventoryStore.set(key, record);
  if (selectedInventoryKey === key) renderInventoryDetail(record);
  renderInventory();
  return true;
}

function upsertFinding(payload) {
  const record = findingRecord(payload);
  if (!record) return false;
  const key = findingKey(record);
  findingStore.set(key, record);
  if (selectedFindingKey === key) renderFindingDetail(record);
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
  if (selectedInventoryKey !== null && !inventoryStore.has(selectedInventoryKey)) {
    selectedInventoryKey = null;
    setSelectionPlaceholder(inventorySelectionDetail, "Ayrıntı için bir kayıt seç.");
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
  if (selectedFindingKey !== null && !findingStore.has(selectedFindingKey)) {
    selectedFindingKey = null;
    setSelectionPlaceholder(findingSelectionDetail, "Ayrıntı için bir bulgu seç.");
  }
  renderFindings();
  return true;
}

function clearResults() {
  inventoryStore.clear();
  findingStore.clear();
  inventoryGroupOpenState.clear();
  findingGroupOpenState.clear();
  selectedInventoryKey = null;
  selectedFindingKey = null;
  setSelectionPlaceholder(inventorySelectionDetail, "Ayrıntı için bir kayıt seç.");
  setSelectionPlaceholder(findingSelectionDetail, "Ayrıntı için bir bulgu seç.");
  renderInventory();
  renderFindings();
}

function showErrors(errors) {
  previewErrors.replaceChildren();
  for (const error of errors) {
    const line = document.createElement("p");
    const rawReason = String(error.reason ?? "");
    const reason = rawReason.startsWith("HASH_TOOL_")
      ? hashToolErrorMessage(rawReason)
      : rawReason;
    const value = error.value === "Hash tools" ? uiText("Hash Araçları") : error.value;
    line.textContent = `${value || (currentLanguage === "en" ? "Input" : "Girdi")}: ${reason}`;
    previewErrors.append(line);
  }
  previewErrors.hidden = errors.length === 0;
}

function mutationHeaders() {
  return {
    "Content-Type": "application/json",
    "Origin": origin,
    "X-CSRF-Token": csrfToken,
  };
}

function syncCredentialControls() {
  const hashSelected = credentialKind.value === "nt_hash";
  const ccacheSelected = credentialKind.value === "ccache";
  credentialSecretLabel.textContent = hashSelected ? "NT hash" : uiText("Parola");
  credentialUsernameLabel.textContent = ccacheSelected
    ? uiText("Kullanıcı (isteğe bağlı)")
    : uiText("Kullanıcı");
  credentialUsername.required = !ccacheSelected;

  credentialSecret.value = "";
  credentialSecretField.hidden = ccacheSelected;
  credentialSecret.disabled = ccacheSelected;
  credentialSecret.required = !ccacheSelected;
  credentialCcacheField.hidden = !ccacheSelected;
  credentialCcache.disabled = !ccacheSelected;
  credentialCcache.required = ccacheSelected;
  credentialCcache.setCustomValidity("");
  if (!ccacheSelected) credentialCcache.value = "";

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
    option.disabled = (hashSelected && option.value !== "ntlm_only")
      || (ccacheSelected && option.value !== "kerberos_only");
  }
  authMode.value = ccacheSelected ? "kerberos_only" : hashSelected ? "ntlm_only" : "auto";
  authMode.disabled = hashSelected || ccacheSelected;
}

function ccacheValidationMessage(file) {
  if (!file) return uiText("CCache dosyası seçilmelidir.");
  if (!file.name.toLocaleLowerCase("tr-TR").endsWith(".ccache")) {
    return uiText("Yalnız .ccache uzantılı dosya seçilebilir.");
  }
  if (file.size === 0) return uiText("CCache dosyası boş olamaz.");
  if (file.size > CCACHE_MAX_BYTES) return uiText("CCache dosyası en fazla 1 MiB olabilir.");
  return "";
}

function ccacheIsValid({report = false} = {}) {
  if (credentialKind.value !== "ccache") return true;
  const message = ccacheValidationMessage(credentialCcache.files?.[0]);
  credentialCcache.setCustomValidity(message);
  if (report) credentialCcache.reportValidity();
  return message === "";
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 16 * 1024;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

async function credentialPayload() {
  const kind = credentialKind.value;
  if (kind === "ccache") {
    const file = credentialCcache.files?.[0];
    const validationMessage = ccacheValidationMessage(file);
    if (validationMessage) throw new CredentialInputError(validationMessage);

    let buffer;
    try {
      buffer = await file.arrayBuffer();
    } catch (_error) {
      throw new CredentialInputError(uiText("CCache dosyası okunamadı."));
    }
    if (buffer.byteLength > CCACHE_MAX_BYTES) {
      throw new CredentialInputError(uiText("CCache dosyası en fazla 1 MiB olabilir."));
    }
    return {
      kind: "ccache",
      auth_mode: "kerberos_only",
      domain: credentialDomain.value.trim() || null,
      username: credentialUsername.value.trim() || null,
      ccache_name: file.name,
      ccache_base64: arrayBufferToBase64(buffer),
    };
  }

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
  if (credentialKind.value === "ccache") return ccacheIsValid({report: true});
  return credentialUsername.reportValidity() && credentialSecret.reportValidity();
}

function additionalSearchTerms() {
  const terms = [];
  const seen = new Set();
  for (const line of additionalTermsInput.value.split(/\r?\n/u)) {
    if (line.trimStart().startsWith("#")) continue;
    for (const value of line.split(",")) {
      const term = value.trim();
      const key = term.toLocaleLowerCase("tr-TR");
      if (!term || seen.has(key)) continue;
      seen.add(key);
      terms.push(term);
    }
  }
  return terms;
}

function setAdditionalTermsStatus(message, tone = "") {
  additionalTermsStatus.textContent = message;
  additionalTermsStatus.className = `additional-terms-status summary${tone ? ` ${tone}` : ""}`;
}

async function importAdditionalTerms() {
  const file = additionalTermsFile.files?.[0];
  if (!file) return;
  try {
    if (!file.name.toLocaleLowerCase("tr-TR").endsWith(".txt")) {
      throw new CredentialInputError(uiText("Yalnız .txt dosyası seçilebilir"));
    }
    if (file.size > CUSTOM_TERMS_MAX_BYTES) {
      throw new CredentialInputError(uiText("TXT dosyası en fazla 1 MiB olabilir"));
    }
    additionalTermsInput.value = await file.text();
    const count = additionalSearchTerms().length;
    setAdditionalTermsStatus(
      currentLanguage === "en"
        ? `${count.toLocaleString(numberLocale())} custom terms imported.`
        : `${count.toLocaleString(numberLocale())} özel terim içe aktarıldı.`,
      "is-ok",
    );
    searchSelectionIsValid();
  } catch (error) {
    const message = error instanceof CredentialInputError
      ? error.message
      : uiText("TXT dosyası okunamadı");
    setAdditionalTermsStatus(message, "is-error");
  } finally {
    additionalTermsFile.value = "";
  }
}

function selectedRulePacks() {
  return patternRulePackInputs
    .filter((input) => input.checked)
    .map((input) => input.value);
}

function rulePacksAreValid({report = false} = {}) {
  const firstInput = patternRulePackInputs[0];
  if (!firstInput) return true;
  const valid = !detectPatternsInput.checked || selectedRulePacks().length > 0;
  firstInput.setCustomValidity(valid ? "" : uiText("En az bir kural grubu seç."));
  if (!valid && report) firstInput.reportValidity();
  return valid;
}

function syncRulePackControls() {
  const enabled = detectPatternsInput.checked;
  for (const input of patternRulePackInputs) input.disabled = !enabled;
  rulePackSelector.classList.toggle("is-disabled", !enabled);
  rulePackCount.textContent = `${selectedRulePacks().length}/${patternRulePackInputs.length}`;
  rulePacksAreValid();
  searchSelectionIsValid();
}

function searchSelectionIsValid({report = false} = {}) {
  const valid = detectPatternsInput.checked || additionalSearchTerms().length > 0;
  additionalTermsInput.setCustomValidity(
    valid ? "" : uiText("Veri kalıplarını açın veya en az bir özel terim girin."),
  );
  if (!valid && report) additionalTermsInput.reportValidity();
  return valid;
}

function detectionRulePackLabel(pack) {
  return uiText(DETECTION_RULE_PACK_LABELS[pack] ?? pack);
}

function scanSearchOptions() {
  return {
    additional_terms: additionalSearchTerms(),
    detect_patterns: detectPatternsInput.checked,
    rule_packs: selectedRulePacks(),
  };
}

function scanTargetInputs(value) {
  return value
    .split(/[\n,]+/u)
    .map((target) => target.trim())
    .filter(Boolean);
}

function captureScanInputs(credential, search) {
  const storedCredential = {
    domain: credential.domain,
    username: credential.username,
    kind: credential.kind,
    auth_mode: credential.auth_mode,
  };
  if (credential.kind === "password") storedCredential.password = credential.password;
  if (credential.kind === "nt_hash") storedCredential.nt_hash = credential.nt_hash;
  if (credential.kind === "ccache") {
    const file = credentialCcache.files?.[0];
    storedCredential.ccache_name = credential.ccache_name;
    storedCredential.ccache_size = file?.size ?? null;
  }

  return {
    name: scanName.value.trim(),
    targets: targets.value.trim(),
    target_list: scanTargetInputs(targets.value),
    test_write_access: testWriteAccessInput.checked,
    credential: storedCredential,
    search: {
      additional_terms: [...search.additional_terms],
      additional_terms_input: additionalTermsInput.value.trim(),
      detect_patterns: search.detect_patterns,
      rule_packs: [...search.rule_packs],
    },
  };
}

function generatorRoots() {
  return [...new Set(
    termGeneratorRoots.value
      .split(/[\n,]+/u)
      .map((root) => root.trim().replace(/\s+/gu, " "))
      .filter(Boolean),
  )];
}

function generatorSeparatorForms(root) {
  const words = root.split(/[\s_-]+/u).filter(Boolean);
  return [...new Set([
    root,
    words.join("_"),
    words.join("-"),
    words.join(" "),
  ])];
}

function generatorJoin(left, right, separator) {
  return `${left}${separator}${right.split(" ").join(separator)}`;
}

function generatedTerms() {
  const terms = new Set();
  const credentialFields = generateCredentialTerms.checked
    ? GENERATOR_CREDENTIAL_FIELDS
    : [];
  const environments = generateEnvironmentTerms.checked
    ? GENERATOR_ENVIRONMENTS
    : [];

  for (const root of generatorRoots()) {
    for (const base of generatorSeparatorForms(root)) {
      terms.add(base);
      for (const field of credentialFields) {
        for (const separator of ["_", "-", " "]) {
          terms.add(generatorJoin(base, field, separator));
          terms.add(generatorJoin(field, base, separator));
        }
      }
      for (const environment of environments) {
        for (const separator of ["_", "-"]) {
          terms.add(generatorJoin(base, environment, separator));
          terms.add(generatorJoin(environment, base, separator));
        }
      }
      if (terms.size >= MAX_GENERATED_TERMS) return [...terms].slice(0, MAX_GENERATED_TERMS);
    }
  }
  return [...terms];
}

function addGeneratedTerms() {
  const roots = generatorRoots();
  if (roots.length === 0) {
    termGeneratorStatus.textContent = uiText("Kök ifade girin.");
    termGeneratorStatus.className = "term-generator-status is-error";
    return;
  }

  const existing = additionalSearchTerms();
  const seen = new Set(existing.map((term) => term.toLocaleLowerCase("tr-TR")));
  const newTerms = [];
  for (const term of generatedTerms()) {
    const key = term.toLocaleLowerCase("tr-TR");
    if (seen.has(key)) continue;
    seen.add(key);
    newTerms.push(term);
  }
  additionalTermsInput.value = [...existing, ...newTerms].join("\n");
  termGeneratorStatus.textContent = newTerms.length > 0
    ? currentLanguage === "en"
      ? `${newTerms.length} new terms added.`
      : `${newTerms.length} yeni terim eklendi.`
    : uiText("Yeni terim yok.");
  termGeneratorStatus.className = "term-generator-status";
}

function scanFormIsValid() {
  return credentialIsValid()
    && rulePacksAreValid({report: true})
    && searchSelectionIsValid({report: true});
}


function saveCompletedScan(state) {
  if (state.status !== "completed" || !state.scan_id) return;
  const history = storedHistory();
  const existing = history.find((item) => item.scan_id === state.scan_id);
  const capturedInputs = scanInputSnapshots.get(state.scan_id) ?? pendingScanInputs;
  const snapshot = {
    targets_snapshot: [...targetStore.values()],
    inventory_items: [...inventoryStore.values()],
    finding_items: [...findingStore.values()],
  };
  if (existing) {
    const resultsUnchanged = JSON.stringify({
      targets_snapshot: existing.targets_snapshot ?? [],
      inventory_items: existing.inventory_items ?? [],
      finding_items: existing.finding_items ?? [],
    }) === JSON.stringify(snapshot);
    const inputsUnchanged = capturedInputs === null || capturedInputs === undefined || JSON.stringify({
      name: existing.name ?? "",
      targets: existing.targets ?? "",
      target_list: existing.target_list ?? [],
      test_write_access: existing.test_write_access ?? false,
      credential: existing.credential ?? {},
      search: existing.search,
    }) === JSON.stringify(capturedInputs);
    if (resultsUnchanged && inputsUnchanged) {
      scanInputSnapshots.delete(state.scan_id);
      return;
    }
    Object.assign(existing, {
      findings: state.finding_count ?? findingStore.size,
      inventory: state.inventory_count ?? inventoryStore.size,
      ...(capturedInputs ?? {}),
      ...snapshot,
    });
    writeHistory(history);
    renderHistory();
    scanInputSnapshots.delete(state.scan_id);
    return;
  }
  const inputs = capturedInputs ?? {
    name: scanName.value.trim(),
    targets: targets.value.trim(),
    target_list: scanTargetInputs(targets.value),
    test_write_access: testWriteAccessInput.checked,
    credential: {
      domain: credentialDomain.value.trim() || null,
      username: credentialUsername.value.trim() || null,
      kind: credentialKind.value,
      auth_mode: authMode.value,
    },
    search: scanSearchOptions(),
  };
  history.unshift({
    scan_id: state.scan_id,
    ...inputs,
    status: "completed",
    findings: state.finding_count ?? findingStore.size,
    inventory: state.inventory_count ?? inventoryStore.size,
    ...snapshot,
    finished_at: new Date().toISOString(),
  });
  setSelectedHistoryKey(state.scan_id);
  scanInputSnapshots.delete(state.scan_id);
  if (pendingScanInputs === capturedInputs) pendingScanInputs = null;
  writeHistory(history);
  renderHistory();
}

function exportResults() {
  const payload = {
    exported_at: new Date().toISOString(),
    targets: [...targetStore.values()],
    inventory: [...inventoryStore.values()],
    findings: [...findingStore.values()],
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `nordis-scan-${new Date().toISOString().replaceAll(":", "-")}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

async function startScan() {
  if (!scanFormIsValid()) return;
  startScanButton.disabled = true;
  showErrors([]);
  let inputSnapshot = null;

  try {
    const credential = await credentialPayload();
    const search = scanSearchOptions();
    inputSnapshot = captureScanInputs(credential, search);
    scanInputSnapshots.clear();
    pendingScanInputs = inputSnapshot;
    const response = await fetch("/scan", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: mutationHeaders(),
      body: JSON.stringify({
        targets: targets.value,
        credential,
        search,
        test_write_access: testWriteAccessInput.checked,
      }),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      const errors = payload.errors ?? [payload.error ?? {value: "İstek", reason: "Doğrulanamadı."}];
      showErrors(errors.map((item) => ({
        value: item.value ?? item.code,
        reason: item.reason ?? item.message,
      })));
      if (pendingScanInputs === inputSnapshot) pendingScanInputs = null;
      return;
    }
    scanInputSnapshots.set(payload.scan_id, inputSnapshot);
    if (pendingScanInputs === inputSnapshot) pendingScanInputs = null;

    targetStore.clear();
    selectedTargetKey = null;
    setSelectionPlaceholder(targetSelectionDetail, "Ayrıntı için bir hedef seç.");
    renderTargetRows("Hedef sonuçları bekleniyor.");
    clearResults();
    activateResultTab("targets");
    cancelScanButton.disabled = false;
    await refreshSnapshot();
    await refreshHashTools();
  } catch (error) {
    if (pendingScanInputs === inputSnapshot) pendingScanInputs = null;
    if (error instanceof CredentialInputError) {
      showErrors([{value: "CCache", reason: error.message}]);
    } else {
      showErrors([{value: uiText("Bağlantı"), reason: uiText("Yerel panel yanıt vermedi.")}]);
    }
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
      headers: mutationHeaders(),
      body: "{}",
    });
    if (response.ok) {
      // The main progress panel reflects the cancelling state via SSE.
    }
  } catch (_error) {
    showErrors([{value: uiText("İptal"), reason: uiText("Yerel panel yanıt vermedi.")}]);
  }
}

function setScanState(state) {
  const status = String(state.status ?? "idle").toLowerCase();
  const phase = String(state.progress?.phase ?? "").toLowerCase();
  const terminal = ["completed", "cancelled", "failed"].includes(status);
  scanPhase.textContent = terminal
    ? localizedMap(SCAN_STATUS_LABELS, EN_SCAN_STATUS_LABELS, status)
    : localizedMap(PHASE_LABELS, EN_PHASE_LABELS, phase)
      ?? localizedMap(SCAN_STATUS_LABELS, EN_SCAN_STATUS_LABELS, status)
      ?? (currentLanguage === "en" ? "Unknown" : "Bilinmiyor");

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
  let progressMessage;
  if (status === "failed") {
    progressMessage = terminalFailureMessage(state)
      ?? (rawMessage
        ? currentLanguage === "en" ? rawMessage : MESSAGE_LABELS[rawMessage] ?? rawMessage
        : null)
      ?? localizedMap(STATUS_MESSAGES, EN_STATUS_MESSAGES, "failed");
  } else if (terminal) {
    progressMessage = localizedMap(STATUS_MESSAGES, EN_STATUS_MESSAGES, status);
  } else {
    progressMessage = rawMessage
      ? currentLanguage === "en" ? rawMessage : MESSAGE_LABELS[rawMessage] ?? rawMessage
      : localizedMap(STATUS_MESSAGES, EN_STATUS_MESSAGES, status) ?? "";
  }
  document.querySelector("#progress-message").textContent = progressMessage;
  saveCompletedScan(state);

  document.querySelector("#inventory-count").textContent = state.inventory_count ?? 0;
  document.querySelector("#finding-count").textContent = state.finding_count ?? 0;
  const active = ["running", "cancelling"].includes(status);
  startScanButton.disabled = active;
  cancelScanButton.disabled = !active || status === "cancelling";
  setHashScanActive(active);
}

function terminalFailureMessage(state) {
  const error = state.terminal_error;
  if (!error || typeof error !== "object" || Array.isArray(error)) return null;

  const phaseKey = typeof error.phase === "string" ? error.phase.toLowerCase() : "";
  const phase = localizedMap(PHASE_LABELS, EN_PHASE_LABELS, phaseKey) ?? error.phase;
  const parts = [phase, error.code, error.message]
    .filter((value) => value !== null && value !== undefined && value !== "")
    .map((value) => String(value));
  return [...new Set(parts)].join(" · ") || null;
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
    // Live events and the next snapshot can still update these views.
  }
}

async function refreshSnapshot() {
  try {
    const response = await fetch("/scan/snapshot", {cache: "no-store", credentials: "omit"});
    if (!response.ok) return;
    const state = await response.json();
    if (latestGeneration !== null && state.generation !== latestGeneration) {
      targetStore.clear();
      selectedTargetKey = null;
      setSelectionPlaceholder(targetSelectionDetail, "Ayrıntı için bir hedef seç.");
      clearResults();
    }
    latestGeneration = state.generation;
    setScanState(state);
    targetsFromSnapshot(state);
    resultsFromSnapshot(state);
    saveCompletedScan(state);
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
      saveCompletedScan(payload);
    }
  } catch (_error) {
    // Invalid or incomplete live events are ignored; the snapshot remains authoritative.
  }
}

configureHashTools({
  activateWorkspace,
  displayValue,
  findingKey,
  findingStore,
  formatFileSize,
  hashFormatLabel,
  hashJobLabel,
  mutationHeaders,
  responsePayload,
});
configureHistory({
  activateResultTab,
  detailList,
  detectionRulePackLabel,
  displayValue,
  formatFileSize,
  replaceFindings,
  replaceInventory,
  replaceTargets,
  setSelectionPlaceholder,
});

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

for (const tab of resultTabs) {
  tab.addEventListener("click", () => activateResultTab(tab.dataset.resultTab));
  tab.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const current = resultTabs.indexOf(tab);
    const offset = event.key === "ArrowRight" ? 1 : -1;
    const next = resultTabs[(current + offset + resultTabs.length) % resultTabs.length];
    activateResultTab(next.dataset.resultTab);
    next.focus();
  });
}

for (const item of workspaceNavigationItems) {
  item.addEventListener("click", () => activateWorkspace(item.dataset.workspaceView));
}

toggleTermGenerator.addEventListener("click", () => {
  termGenerator.hidden = !termGenerator.hidden;
  toggleTermGenerator.setAttribute("aria-expanded", String(!termGenerator.hidden));
  if (!termGenerator.hidden) termGeneratorRoots.focus();
});
generateTermsButton.addEventListener("click", addGeneratedTerms);
detectPatternsInput.addEventListener("change", syncRulePackControls);
additionalTermsInput.addEventListener("input", () => {
  setAdditionalTermsStatus("");
  searchSelectionIsValid();
});
additionalTermsFile.addEventListener("change", importAdditionalTerms);
for (const input of patternRulePackInputs) {
  input.addEventListener("change", syncRulePackControls);
}

startScanButton.addEventListener("click", startScan);
cancelScanButton.addEventListener("click", cancelScan);
credentialKind.addEventListener("change", syncCredentialControls);
credentialCcache.addEventListener("change", () => ccacheIsValid());
inventoryFilter.addEventListener("input", renderInventory);
findingsFilter.addEventListener("input", renderFindings);
languageSelect.value = currentLanguage;
if (currentLanguage === "en") applyLanguage(currentLanguage);
syncCredentialControls();
syncRulePackControls();
activateWorkspace("scan");
activateResultTab("targets");
refreshSnapshot();
refreshResultPanels();
refreshHashTools();

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

exportResultsButton.addEventListener("click", exportResults);
renderHistory();
languageSelect.addEventListener("change", () => {
  localStorage.setItem(LANGUAGE_KEY, languageSelect.value);
  window.location.reload();
});
