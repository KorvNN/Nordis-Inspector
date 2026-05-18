"use strict";

const body = document.body;
const csrfToken = body.dataset.csrfToken;
const origin = body.dataset.origin;
const targets = document.querySelector("#targets");
const scanProfile = document.querySelector("#scan-profile");
const saveProfileButton = document.querySelector("#save-profile");
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
const toggleTermGenerator = document.querySelector("#toggle-term-generator");
const termGenerator = document.querySelector("#term-generator");
const termGeneratorRoots = document.querySelector("#term-generator-roots");
const generateCredentialTerms = document.querySelector("#generate-credential-terms");
const generateEnvironmentTerms = document.querySelector("#generate-environment-terms");
const generateTermsButton = document.querySelector("#generate-terms");
const termGeneratorStatus = document.querySelector("#term-generator-status");
const detectPatternsInput = document.querySelector("#detect-patterns");
const contentWordlist = document.querySelector("#content-wordlist");
const contentWordlistFile = document.querySelector("#content-wordlist-file");
const contentWordlistCount = document.querySelector("#content-wordlist-count");
const contentWordlistStatus = document.querySelector("#content-wordlist-status");
const saveContentWordlist = document.querySelector("#save-content-wordlist");
const openWordlistsButton = document.querySelector("#open-wordlists");
const closeWordlistsButton = document.querySelector("#close-wordlists");
const wordlistDialog = document.querySelector("#wordlist-dialog");
const startScanButton = document.querySelector("#start-scan-button");
const cancelScanButton = document.querySelector("#cancel-scan-button");
const scopeState = document.querySelector("#scope-state");
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
const historyTabCount = document.querySelector("#history-tab-count");
const scanHistory = document.querySelector("#scan-history");
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
let lastSavedGeneration = null;

const HISTORY_KEY = "nordis.scan-history.v1";
const PROFILE_KEY = "nordis.scan-profile.v1";
const SCAN_PROFILES = {
  quick: {detect_patterns: false},
  balanced: {detect_patterns: true},
  deep: {detect_patterns: true},
};

const CCACHE_MAX_BYTES = 1024 * 1024;
const WORDLIST_MAX_BYTES = 1024 * 1024;
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
const WORDLIST_EDITORS = {
  content: {
    count: contentWordlistCount,
    editor: contentWordlist,
    file: contentWordlistFile,
    save: saveContentWordlist,
    status: contentWordlistStatus,
  },
};

class CredentialInputError extends Error {}

const ATTENTION_STATUS = /(?:DENIED|FAILED|ERROR|REFUSED|TIMEOUT|UNREACHABLE|UNAVAILABLE|VIOLATION)/u;
const WORKING_STATUS = /(?:PENDING|CONNECTING|NEGOTIATING|AUTHENTICATING|SCANNING|RUNNING)/u;
const OK_STATUS = /(?:OPEN|READY|SUCCESS|AUTHENTICATED|DOĞRULANDI|KERBEROS|NTLM|COMPLETED|PARTIAL_ACCESS)/u;
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
  share_enum_denied: "Share listesi reddedildi",
  share_enum_unavailable: "Share listesi alınamıyor",
  share_enum_failed: "Share keşfi başarısız",
  partial_access: "Kısmi erişim",
  security_active_required: "Aktif · Zorunlu",
  security_active: "Aktif",
  security_required: "Zorunlu",
  security_supported: "Destekli",
  security_unsupported: "Desteklenmiyor",
  cancelled: "İptal edildi",
  completed: "Tamamlandı",
  failed: "Başarısız",
  wordlist: "Wordlist",
  pattern: "Kalıp",
  high: "Yüksek",
  medium: "Orta",
  allowed: "İzin var",
  denied: "Reddedildi",
  unknown: "Bilinmiyor",
  error: "Hata",
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
  inspection: "SMB ve içerik taraması",
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
const ERROR_MESSAGE_LABELS = {
  "The target refused the TCP connection.": "Hedef TCP bağlantısını reddetti.",
  "The local network stack reported that the target is unreachable.": "Hedef ağa ulaşılamıyor.",
  "No TCP response was received before the configured timeout.": "Süre dolmadan TCP yanıtı alınamadı.",
  "SMB authentication failed.": "SMB kimlik doğrulaması başarısız.",
  "The supplied credential was not accepted.": "Girilen kimlik bilgisi kabul edilmedi.",
  "The supplied credential has expired.": "Girilen kimlik bilgisinin süresi dolmuş.",
  "The account cannot connect to this share.": "Hesabın bu share'e erişimi reddedildi.",
  "The named share was not found.": "Belirtilen share bulunamadı.",
  "The directory could not be listed.": "Dizin listelenemedi.",
  "The file is visible but read access was denied.": "Dosya görünüyor fakat okuma erişimi reddedildi.",
  "The visible file could not be opened for reading.": "Görünen dosya okumak için açılamadı.",
};

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
  placeholder.textContent = message;
  container.replaceChildren(placeholder);
}

function detailList(fields) {
  const list = document.createElement("dl");
  list.className = "detail-list";
  for (const [label, value, className = ""] of fields) {
    const group = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
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
    signing: securityFeatureValue(candidate, "signing"),
    encryption: securityFeatureValue(candidate, "encryption"),
    authentication: targetAuthenticationValue(candidate),
    lastStatus: firstValue(candidate, ["last_status", "final_status", "status", "last_stage"]),
    detail: targetErrorDetail(candidate) ?? targetErrorDetail(payload),
    sharesProbed: firstValue(candidate, ["shares_probed"]),
    sharesAccessible: firstValue(candidate, ["shares_accessible"]),
    filesSeen: firstValue(candidate, ["files_seen"]),
    filesScanned: firstValue(candidate, ["files_scanned"]),
    unreadableFiles: firstValue(candidate, ["unreadable_files"]),
  };
}

function renderTargetDetail(record) {
  renderSelectionDetail(targetSelectionDetail, record.ip, [
    ["TCP/445", record.tcp],
    ["SMB dialect", record.smb],
    ["Signing", record.signing],
    ["Encryption", record.encryption],
    ["Kimlik doğrulama", record.authentication],
    ["Son durum", record.lastStatus],
    ["Denenen share", record.sharesProbed],
    ["Erişilen share", record.sharesAccessible],
    ["Görülen dosya", record.filesSeen],
    ["Taranan dosya", record.filesScanned],
    ["Okunamayan dosya", record.unreadableFiles],
    ["Hata ayrıntısı", record.detail],
  ]);
}

function targetAuthenticationValue(record) {
  const method = firstValue(record, ["authentication_method", "auth_method"]);
  if (method !== null) return `Doğrulandı · ${displayValue(method)}`;
  return firstValue(record, ["authentication_status", "auth_status"]);
}

function targetErrorDetail(record) {
  const values = [record.error_name, record.raw_error_code, record.error_message]
    .filter((value) => value !== null && value !== undefined && value !== "")
    .map((value) => ERROR_MESSAGE_LABELS[String(value)] ?? String(value));
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
  targetWorkspaceCount.textContent = records.length.toLocaleString("tr-TR");
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
    readAccess: firstValue(candidate, ["read_access"]),
    writeAccess: firstValue(candidate, ["write_access"]),
    size: firstValue(candidate, ["size", "size_bytes", "file_size"]),
    modifiedAt: firstValue(candidate, ["modified_at", "modified", "mtime"]),
    detail: targetErrorDetail(candidate),
  };
}

function inventoryKey(record) {
  if (record.id !== null) return `id:${String(record.id)}`;
  return [record.target, record.share, record.path, record.type]
    .map((value) => displayValue(value))
    .join("\u001f");
}

function renderInventoryDetail(record) {
  renderSelectionDetail(inventorySelectionDetail, record.path, [
    ["Hedef", record.target],
    ["Share", record.share],
    ["Path", record.path],
    ["Tür", record.type],
    ["Durum", record.status],
    ["Okuma", record.readAccess],
    ["Yazma", record.writeAccess],
    ["Boyut", formatSize(record.size)],
    ["Değiştirilme", record.modifiedAt],
    ["Hata ayrıntısı", record.detail],
  ]);
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
    method: firstValue(candidate, ["method", "detection_method"]),
    ruleId: firstValue(candidate, ["rule_id", "rule"]),
    category: firstValue(candidate, ["category", "rule_category"]),
    confidence: firstValue(candidate, ["confidence", "confidence_level"]),
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

  const signal = document.createElement("section");
  signal.className = "finding-signal";
  const signalLabel = document.createElement("span");
  signalLabel.className = "finding-signal-label";
  signalLabel.textContent = "Eşleşme";
  const signalValue = document.createElement("strong");
  signalValue.className = "finding-signal-value";
  signalValue.textContent = displayValue(record.term);
  signal.append(signalLabel, signalValue);

  const context = document.createElement("section");
  context.className = "finding-context";
  const contextLabel = document.createElement("span");
  contextLabel.className = "finding-context-label";
  contextLabel.textContent = "Satır içeriği";
  const line = document.createElement("code");
  appendHighlightedText(line, record.fullLine, record.term);
  context.append(contextLabel, line);

  const metadata = detailList([
    ["Hedef", record.target, "detail-code"],
    ["Share", record.share, "detail-code"],
    ["Satır no", record.lineNumber, "detail-code"],
    ["Yöntem", record.method],
    ["Kural", record.ruleId, "detail-code"],
    ["Kategori", record.category],
    ["Güven", record.confidence],
  ]);
  metadata.classList.add("finding-metadata");
  findingSelectionDetail.replaceChildren(header, signal, context, metadata);
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
  countLabel,
  tableClass,
  headings,
  rowForRecord,
}) {
  const details = document.createElement("details");
  details.className = "result-group";
  details.dataset.groupTarget = target;
  details.open = openState.has(target) ? openState.get(target) : defaultOpen;
  details.addEventListener("toggle", () => openState.set(target, details.open));

  const summary = document.createElement("summary");
  const targetLabel = document.createElement("span");
  targetLabel.className = "result-group-target";
  targetLabel.textContent = target;
  const count = document.createElement("span");
  count.className = "result-group-count";
  count.textContent = `${records.length.toLocaleString("tr-TR")} ${countLabel}`;
  summary.append(targetLabel, count);

  const frame = document.createElement("div");
  frame.className = "group-table-frame";
  const table = document.createElement("table");
  table.className = `result-table ${tableClass}`;
  const head = document.createElement("thead");
  const headingRow = document.createElement("tr");
  for (const heading of headings) {
    const cell = document.createElement("th");
    cell.scope = "col";
    cell.textContent = heading;
    headingRow.append(cell);
  }
  head.append(headingRow);
  const bodyElement = document.createElement("tbody");
  for (const item of records) bodyElement.append(rowForRecord(item));
  table.append(head, bodyElement);
  frame.append(table);
  details.append(summary, frame);
  return details;
}

function renderInventory() {
  const visibleRecords = [...inventoryStore].filter(([, record]) => recordMatchesSearch(
    record,
    inventoryFilter.value,
    ["target", "share", "path", "type", "status", "size", "detail"],
  ));
  if (!visibleRecords.some(([key]) => key === selectedInventoryKey)) {
    selectedInventoryKey = visibleRecords[0]?.[0] ?? null;
    if (visibleRecords[0]) renderInventoryDetail(visibleRecords[0][1]);
    else setSelectionPlaceholder(inventorySelectionDetail, "Ayrıntı için bir kayıt seç.");
  }
  const groups = recordsByTarget(visibleRecords);
  inventoryGroups.replaceChildren();
  let groupIndex = 0;
  for (const [target, records] of groups) {
    inventoryGroups.append(groupedResult({
      target,
      records,
      openState: inventoryGroupOpenState,
      defaultOpen: groupIndex === 0,
      countLabel: "kayıt",
      tableClass: "inventory-table",
      headings: ["Share", "Path", "Durum"],
      rowForRecord: ([key, record]) => {
        const row = document.createElement("tr");
        row.append(textCell(record.share));
        row.append(textCell(record.path, "path-value"));
        row.append(textCell(record.status, `status-value ${statusTone(record.status)}`));
        bindSelectableRow(row, {
          selected: selectedInventoryKey === key,
          select: () => {
            selectedInventoryKey = key;
            renderInventory();
            renderInventoryDetail(record);
          },
        });
        return row;
      },
    }));
    groupIndex += 1;
  }
  if (visibleRecords.length === 0) {
    setGroupedResultMessage(
      inventoryGroups,
      inventoryStore.size === 0 ? "Henüz envanter yok." : "Filtreyle eşleşen kayıt yok.",
    );
  }
  inventoryVisibleCount.textContent = `${visibleRecords.length.toLocaleString("tr-TR")} kayıt`;
  inventoryTabCount.textContent = inventoryStore.size.toLocaleString("tr-TR");
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
    else setSelectionPlaceholder(findingSelectionDetail, "Tam satır için bir bulgu seç.");
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
      headings: ["Dosya", "Satır no", "Yöntem", "Eşleşme"],
      rowForRecord: ([key, record]) => {
        const row = document.createElement("tr");
        row.append(textCell(record.file, "path-value"));
        row.append(textCell(record.lineNumber, "code-value"));
        row.append(textCell(record.method, `status-value ${statusTone(record.method)}`));
        row.append(textCell(record.term, "finding-term-pill"));
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
  findingsVisibleCount.textContent = `${visibleRecords.length.toLocaleString("tr-TR")} bulgu`;
  findingsTabCount.textContent = findingStore.size.toLocaleString("tr-TR");
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
    setSelectionPlaceholder(findingSelectionDetail, "Tam satır için bir bulgu seç.");
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
  setSelectionPlaceholder(findingSelectionDetail, "Tam satır için bir bulgu seç.");
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

function mutationHeaders() {
  return {
    "Content-Type": "application/json",
    "Origin": origin,
    "X-CSRF-Token": csrfToken,
  };
}

function wordlistEntryCount(text) {
  const entries = new Set();
  for (const line of text.split(/\r?\n/u)) {
    const entry = line.trim();
    if (entry && !entry.startsWith("#")) entries.add(entry.toLocaleLowerCase("tr-TR"));
  }
  return entries.size;
}

function setWordlistCount(kind, count = null) {
  const controls = WORDLIST_EDITORS[kind];
  const resolvedCount = Number.isInteger(count)
    ? count
    : wordlistEntryCount(controls.editor.value);
  controls.count.textContent = `${resolvedCount.toLocaleString("tr-TR")} kayıt`;
}

function setWordlistStatus(kind, message, tone = "") {
  const status = WORDLIST_EDITORS[kind].status;
  status.textContent = message;
  status.className = `wordlist-status${tone ? ` ${tone}` : ""}`;
}

function wordlistPayload(payload, kind) {
  const candidate = payload?.[kind] ?? payload;
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return null;
  if (typeof candidate.text !== "string") return null;
  return candidate;
}

async function responsePayload(response) {
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

function responseError(payload, fallback) {
  if (typeof payload?.error === "string") return payload.error;
  if (typeof payload?.error?.message === "string") return payload.error.message;
  if (typeof payload?.message === "string") return payload.message;
  return fallback;
}

async function refreshWordlists() {
  for (const kind of Object.keys(WORDLIST_EDITORS)) setWordlistStatus(kind, "Yükleniyor");
  try {
    const response = await fetch("/wordlists", {cache: "no-store", credentials: "omit"});
    const payload = await responsePayload(response);
    if (!response.ok) throw new Error("request_failed");

    for (const kind of Object.keys(WORDLIST_EDITORS)) {
      const item = wordlistPayload(payload, kind);
      if (!item) throw new Error("invalid_payload");
      WORDLIST_EDITORS[kind].editor.value = item.text;
      setWordlistCount(kind, item.entry_count);
      setWordlistStatus(kind, "");
    }
  } catch (_error) {
    for (const kind of Object.keys(WORDLIST_EDITORS)) {
      setWordlistStatus(kind, "Liste yüklenemedi", "is-error");
    }
  }
}

async function saveWordlist(kind) {
  const controls = WORDLIST_EDITORS[kind];
  controls.save.disabled = true;
  setWordlistStatus(kind, "Kaydediliyor");
  try {
    const response = await fetch(`/wordlists/${kind}`, {
      method: "PUT",
      credentials: "omit",
      cache: "no-store",
      headers: mutationHeaders(),
      body: JSON.stringify({text: controls.editor.value}),
    });
    const payload = await responsePayload(response);
    if (!response.ok) {
      setWordlistStatus(
        kind,
        responseError(payload, "Liste kaydedilemedi"),
        "is-error",
      );
      return;
    }

    const item = wordlistPayload(payload, kind);
    if (item) controls.editor.value = item.text;
    setWordlistCount(kind, item?.entry_count);
    setWordlistStatus(kind, "Kaydedildi", "is-ok");
  } catch (_error) {
    setWordlistStatus(kind, "Liste kaydedilemedi", "is-error");
  } finally {
    controls.save.disabled = false;
  }
}

async function importWordlist(kind) {
  const controls = WORDLIST_EDITORS[kind];
  const file = controls.file.files?.[0];
  if (!file) return;

  try {
    if (!file.name.toLocaleLowerCase("tr-TR").endsWith(".txt")) {
      throw new CredentialInputError("Yalnız .txt dosyası seçilebilir");
    }
    if (file.size > WORDLIST_MAX_BYTES) {
      throw new CredentialInputError("TXT dosyası en fazla 1 MiB olabilir");
    }
    controls.editor.value = await file.text();
    setWordlistCount(kind);
    setWordlistStatus(kind, "İçe aktarıldı · kaydedilmedi", "is-ok");
  } catch (error) {
    const message = error instanceof CredentialInputError
      ? error.message
      : "TXT dosyası okunamadı";
    setWordlistStatus(kind, message, "is-error");
  } finally {
    controls.file.value = "";
  }
}

function syncCredentialControls() {
  const hashSelected = credentialKind.value === "nt_hash";
  const ccacheSelected = credentialKind.value === "ccache";
  credentialSecretLabel.textContent = hashSelected ? "NT hash" : "Parola";
  credentialUsernameLabel.textContent = ccacheSelected ? "Kullanıcı (isteğe bağlı)" : "Kullanıcı";
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
  if (!file) return "CCache dosyası seçilmelidir.";
  if (!file.name.toLocaleLowerCase("tr-TR").endsWith(".ccache")) {
    return "Yalnız .ccache uzantılı dosya seçilebilir.";
  }
  if (file.size === 0) return "CCache dosyası boş olamaz.";
  if (file.size > CCACHE_MAX_BYTES) return "CCache dosyası en fazla 1 MiB olabilir.";
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
      throw new CredentialInputError("CCache dosyası okunamadı.");
    }
    if (buffer.byteLength > CCACHE_MAX_BYTES) {
      throw new CredentialInputError("CCache dosyası en fazla 1 MiB olabilir.");
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
  const terms = additionalTermsInput.value
    .split(/[\n,]+/u)
    .map((term) => term.trim())
    .filter(Boolean);
  return [...new Set(terms)];
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
    termGeneratorStatus.textContent = "Kök ifade girin.";
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
    ? `${newTerms.length} yeni terim eklendi.`
    : "Yeni terim yok.";
  termGeneratorStatus.className = "term-generator-status";
}

function scanFormIsValid() {
  return credentialIsValid();
}

function storedHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    return Array.isArray(value) ? value : [];
  } catch (_error) {
    return [];
  }
}

function renderHistory() {
  const history = storedHistory();
  historyTabCount.textContent = history.length;
  scanHistory.replaceChildren();
  if (history.length === 0) {
    const empty = document.createElement("p");
    empty.className = "group-empty-state";
    empty.textContent = "Henüz kayıtlı tarama yok.";
    scanHistory.append(empty);
    return;
  }
  for (const item of history) {
    const row = document.createElement("div");
    row.className = "result-group";
    const title = document.createElement("strong");
    title.textContent = `${item.targets} · ${item.status}`;
    const summary = document.createElement("span");
    summary.className = "summary";
    summary.textContent = `${item.finished_at} · ${item.findings} bulgu · ${item.inventory} envanter`;
    row.append(title, summary);
    scanHistory.append(row);
  }
}

function saveCompletedScan(state) {
  if (state.status !== "completed" || state.generation === lastSavedGeneration) return;
  const history = storedHistory();
  history.unshift({
    scan_id: state.scan_id,
    targets: targets.value.trim() || "Hedefler",
    status: SCAN_STATUS_LABELS.completed,
    findings: state.finding_count ?? findingStore.size,
    inventory: state.inventory_count ?? inventoryStore.size,
    finished_at: new Date().toLocaleString("tr-TR"),
  });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 20)));
  lastSavedGeneration = state.generation;
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

function applyScanProfile() {
  const profile = SCAN_PROFILES[scanProfile.value];
  if (profile) detectPatternsInput.checked = profile.detect_patterns;
}

async function startScan() {
  if (!scanFormIsValid()) return;
  startScanButton.disabled = true;
  setScopeState("Başlatılıyor", "working");
  showErrors([]);

  try {
    const credential = await credentialPayload();
    const response = await fetch("/scan", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: mutationHeaders(),
      body: JSON.stringify({
        targets: targets.value,
        credential,
        search: {
          use_default: true,
          additional_terms: additionalSearchTerms(),
          detect_patterns: detectPatternsInput.checked,
        },
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
    selectedTargetKey = null;
    setSelectionPlaceholder(targetSelectionDetail, "Ayrıntı için bir hedef seç.");
    renderTargetRows("Hedef sonuçları bekleniyor.");
    clearResults();
    activateResultTab("targets");
    setScopeState("Çalışıyor", "working");
    cancelScanButton.disabled = false;
    await refreshSnapshot();
  } catch (error) {
    if (error instanceof CredentialInputError) {
      showErrors([{value: "CCache", reason: error.message}]);
      setScopeState("Hatalı", "error");
    } else {
      showErrors([{value: "Bağlantı", reason: "Yerel panel yanıt vermedi."}]);
      setScopeState("Hata", "error");
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
  let progressMessage;
  if (status === "failed") {
    progressMessage = terminalFailureMessage(state)
      ?? (rawMessage ? MESSAGE_LABELS[rawMessage] ?? rawMessage : null)
      ?? STATUS_MESSAGES.failed;
  } else if (terminal) {
    progressMessage = STATUS_MESSAGES[status];
  } else {
    progressMessage = rawMessage
      ? MESSAGE_LABELS[rawMessage] ?? rawMessage
      : STATUS_MESSAGES[status] ?? "";
  }
  document.querySelector("#progress-message").textContent = progressMessage;
  saveCompletedScan(state);

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

function terminalFailureMessage(state) {
  const error = state.terminal_error;
  if (!error || typeof error !== "object" || Array.isArray(error)) return null;

  const phaseKey = typeof error.phase === "string" ? error.phase.toLowerCase() : "";
  const phase = PHASE_LABELS[phaseKey] ?? error.phase;
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

openWordlistsButton.addEventListener("click", async () => {
  await refreshWordlists();
  wordlistDialog.showModal();
});
closeWordlistsButton.addEventListener("click", () => wordlistDialog.close());
wordlistDialog.addEventListener("click", (event) => {
  if (event.target === wordlistDialog) wordlistDialog.close();
});
toggleTermGenerator.addEventListener("click", () => {
  termGenerator.hidden = !termGenerator.hidden;
  toggleTermGenerator.setAttribute("aria-expanded", String(!termGenerator.hidden));
  if (!termGenerator.hidden) termGeneratorRoots.focus();
});
generateTermsButton.addEventListener("click", addGeneratedTerms);

startScanButton.addEventListener("click", startScan);
cancelScanButton.addEventListener("click", cancelScan);
credentialKind.addEventListener("change", syncCredentialControls);
credentialCcache.addEventListener("change", () => ccacheIsValid());
inventoryFilter.addEventListener("input", renderInventory);
findingsFilter.addEventListener("input", renderFindings);
for (const [kind, controls] of Object.entries(WORDLIST_EDITORS)) {
  controls.editor.addEventListener("input", () => {
    setWordlistCount(kind);
    setWordlistStatus(kind, "");
  });
  controls.file.addEventListener("change", () => importWordlist(kind));
  controls.save.addEventListener("click", () => saveWordlist(kind));
}
syncCredentialControls();
activateResultTab("targets");
refreshSnapshot();
refreshResultPanels();
refreshWordlists();

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

scanProfile.addEventListener("change", applyScanProfile);
detectPatternsInput.addEventListener("change", () => {
  if (scanProfile.value !== "custom") scanProfile.value = "custom";
});
saveProfileButton.addEventListener("click", () => {
  localStorage.setItem(PROFILE_KEY, JSON.stringify({
    profile: scanProfile.value,
    detect_patterns: detectPatternsInput.checked,
  }));
  saveProfileButton.textContent = "Kaydedildi";
  setTimeout(() => { saveProfileButton.textContent = "Ayarları hatırla"; }, 1200);
});
exportResultsButton.addEventListener("click", exportResults);
renderHistory();
try {
  const saved = JSON.parse(localStorage.getItem(PROFILE_KEY) ?? "null");
  if (saved && typeof saved === "object") {
    scanProfile.value = saved.profile ?? "balanced";
    detectPatternsInput.checked = saved.detect_patterns !== false;
  }
} catch (_error) {
  // Invalid local preferences are ignored.
}
