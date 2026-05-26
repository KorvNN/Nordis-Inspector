"use strict";

const body = document.body;
const languageSelect = document.querySelector("#language-select");
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

const HISTORY_KEY = "nordis.scan-history.v1";

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
  share_connected: "Share erişilebilir",
  share_access_denied: "Share erişimi reddedildi",
  non_file_share: "Dosya share'i değil",
  directory_listable: "Dizin listelenebilir",
  directory_list_denied: "Dizin listeleme reddedildi",
  depth_limit_reached: "Derinlik sınırına ulaşıldı",
  file_readable: "Dosya okunabilir",
  file_read_denied: "Dosya okuma reddedildi",
  sharing_violation: "Paylaşım ihlali",
  read_error: "Okuma hatası",
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
  low: "Düşük",
  allowed: "İzin var",
  denied: "Reddedildi",
  unknown: "Bilinmiyor",
  error: "Hata",
};
const FINDING_METHOD_LABELS = {
  wordlist: "Terim listesi eşleşmesi",
  pattern: "Veri kalıbı eşleşmesi",
};
const FINDING_RULE_LABELS = {
  "secret-assignment": "Gizli bilgi ataması",
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
  "The target inspection completed with inaccessible content.": "Hedef incelemesi erişilemeyen içerikle tamamlandı.",
};
const LANGUAGE_KEY = "nordis.dashboard-language";
let currentLanguage = (() => {
  try {
    return localStorage.getItem(LANGUAGE_KEY) === "en" ? "en" : "tr";
  } catch (_error) {
    return "tr";
  }
})();
const EN_STATUS_LABELS = {
  port_open: "Port 445 open", timeout_no_response: "No response / timeout",
  connection_refused: "Connection refused", network_unreachable: "Network unreachable",
  authenticated: "Authenticated", auth_failed: "Authentication failed",
  access_denied: "Access denied", share_enum_denied: "Share listing denied",
  share_enum_unavailable: "Share listing unavailable", share_enum_failed: "Share discovery failed",
  partial_access: "Partial access", completed: "Completed", cancelled: "Cancelled",
  failed: "Failed", high: "High", medium: "Medium", low: "Low",
  allowed: "Allowed", denied: "Denied", unknown: "Unknown", error: "Error",
  wordlist: "Wordlist match", pattern: "Pattern match",
  security_active_required: "Active · Required", security_active: "Active",
  security_required: "Required", security_supported: "Supported", security_unsupported: "Unsupported",
  share_connected: "Share accessible", share_access_denied: "Share access denied",
  non_file_share: "Non-file share", directory_listable: "Directory listable",
  directory_list_denied: "Directory listing denied", depth_limit_reached: "Depth limit reached",
  file_readable: "File readable", file_read_denied: "File read denied",
  sharing_violation: "Sharing violation", read_error: "Read error",
};
const EN_CATEGORY_LABELS = {
  "Cloud / SaaS": "Cloud / SaaS", "Oturum tokenı": "Session token",
  "Kriptografik anahtar": "Cryptographic key", "Kimlik bilgisi": "Credential",
  Veritabanı: "Database", Yapılandırma: "Configuration", "Windows / AD": "Windows / AD",
  "Credential artifact": "Credential artifact", "Source control": "Source control",
  "Ödeme servisi": "Payment service", "Developer tooling": "Developer tooling",
  Infrastructure: "Infrastructure", "Container tooling": "Container tooling",
};
const EN_PHASE_LABELS = {
  preparing_targets: "Preparing targets", connectivity: "TCP/445 check",
  inspection: "SMB and content scan", authentication: "Authentication",
  share_discovery: "Share discovery", file_inventory: "File inventory",
  content_scan: "Content scan", cancelling: "Cancelling", cancelled: "Cancelled",
  completed: "Completed", failed: "Failed",
};
const EN_SCAN_STATUS_LABELS = {idle: "No scan", running: "Running", cancelling: "Cancelling", cancelled: "Cancelled", completed: "Completed", failed: "Failed"};
const EN_STATUS_MESSAGES = {
  idle: "No scan has been started.", cancelling: "Cancelling scan.",
  cancelled: "Scan cancelled.", completed: "Scan completed.", failed: "Scan failed.",
};
const DETAIL_LABELS = {
  "Kimlik doğrulama": "Authentication", "Son durum": "Final status",
  "Denenen share": "Shares probed", "Erişilen share": "Shares accessible",
  "Görülen dosya": "Files seen", "Taranan dosya": "Files scanned",
  "Okunamayan dosya": "Unreadable files", "Hata ayrıntısı": "Error details",
  "Ayrıntı için bir hedef seç.": "Select a target to view details.",
  "Hedef": "Target", "Path": "Path", "Tür": "Type", "Durum": "Status",
  "Okuma": "Read access", "Yazma": "Write access", "Boyut": "Size",
  "Değiştirilme": "Modified", "Eşleşme": "Match", "Satır içeriği": "Line content",
  "Satır no": "Line number", "Yöntem": "Method", "Kural": "Rule",
  "Kategori": "Category", "Güven": "Confidence",
};

function localizedMap(map, englishMap, key) {
  return currentLanguage === "en" ? englishMap[key] : map[key];
}
const LANGUAGE_TEXT = {
  en: {
    "Yeni tarama": "New scan",
    "Bekliyor": "Idle",
    "IP, CIDR veya hostname": "IP, CIDR, or hostname",
    "Tarama adı": "Scan name",
    "Örn. Finans sunucuları": "e.g. Finance servers",
    "Virgül veya yeni satırla ayır.": "Separate with commas or new lines.",
    "Kimlik bilgisi": "Credentials",
    "Kullanıcı": "Username",
    "Kullanıcı (isteğe bağlı)": "Username (optional)",
    "Credential türü": "Credential type",
    "Parola": "Password",
    "CCache dosyası": "CCache file",
    "Kimlik doğrulama": "Authentication",
    "Yalnız Kerberos": "Kerberos only",
    "Yalnız NTLM": "NTLM only",
    "Auto (Kerberos öncelikli)": "Auto (Kerberos preferred)",
    "İçerik arama": "Content search",
    "Wordlist yönetimi": "Wordlist management",
    "Ek arama terimleri": "Additional search terms",
    "Terim üret": "Generate terms",
    "Kök ifadeler": "Root expressions",
    "Credential alanları": "Credential fields",
    "Ortam adları": "Environment names",
    "Ek terimleri üret": "Generate terms",
    "Veri Kalıplarını Aramaya Dahil Et": "Include built-in data patterns",
    "Taramayı başlat": "Start scan",
    "İptal et": "Cancel",
    "Tarama yok": "No scan",
    "Yeni bir tarama başlatılmadı.": "No scan has been started.",
    "Envanter": "Inventory",
    "Bulgu": "Finding",
    "Faz": "Phase",
    "Hedefler": "Targets",
    "Bulgular": "Findings",
    "Geçmiş": "History",
    "Sonuçları JSON indir": "Download results as JSON",
    "Görüntüle": "View",
    "Sil": "Delete",
    "Share'ler": "Shares",
    "Dizinler": "Directories",
    "Dosyalar": "Files",
    "Filtre": "Filter",
    "Son durum": "Final status",
    "Tamamlanan taramalar bu tarayıcıda saklanır.": "Completed scans are stored in this browser.",
    "İçerik arama terimleri": "Content search terms",
    "TXT içe aktar": "Import TXT",
    "Kaydet": "Save",
    "0 hedef": "0 targets",
    "0 kayıt": "0 entries",
    "0 bulgu": "0 findings",
    "— kayıt": "— entries",
    "Ayrıntı için bir hedef seç.": "Select a target to view details.",
    "Ayrıntı için bir kayıt seç.": "Select an entry to view details.",
    "Tam satır için bir bulgu seç.": "Select a finding to view the full line.",
    "Henüz tarama başlatılmadı.": "No scan has been started.",
    "Hedef sonuçları bekleniyor.": "Waiting for target results.",
    "Hedef durumları bekleniyor.": "Waiting for target statuses.",
    "Bu filtreyle eşleşen hedef yok.": "No targets match this filter.",
    "Henüz envanter yok.": "No inventory yet.",
    "Filtreyle eşleşen kayıt yok.": "No entries match this filter.",
    "Henüz bulgu yok.": "No findings yet.",
    "Filtreyle eşleşen bulgu yok.": "No findings match this filter.",
    "Henüz kayıtlı tarama yok.": "No saved scans yet.",
    "Kullanıcı yok": "No username",
    "Bu tarama geçmişten silinsin mi?": "Delete this scan from history?",
    "Dosya": "File",
    "Dizin": "Directory",
    "Share": "Share",
    "Kayıt": "Entry",
    "kayıt": "entries",
    "bulgu": "findings",
    "Yanıt veren": "Responding",
    "TCP açık": "TCP open",
    "SMB hazır": "SMB ready",
    "Doğrulandı": "Authenticated",
    "Sorunlu": "Needs attention",
    "Tarama çalışma alanı": "Scan workspace",
    "Tarama ilerlemesi": "Scan progress",
    "Tarama sonuçları": "Scan results",
    "Hedef durumu filtreleri": "Target status filters",
    "Hedef ayrıntısı": "Target details",
    "Envanter ayrıntısı": "Inventory details",
    "Bulgu ayrıntısı": "Finding details",
    "Kapat": "Close",
    "SMB sürümü": "SMB dialect",
    "İmzalama": "Signing",
    "Şifreleme": "Encryption",
    "Yükleniyor": "Loading",
    "Liste yüklenemedi": "Could not load the list",
    "Kaydediliyor": "Saving",
    "Kaydedildi": "Saved",
    "Liste kaydedilemedi": "Could not save the list",
    "İçe aktarıldı · kaydedilmedi": "Imported · not saved",
    "Kök ifade girin.": "Enter a root expression.",
    "Yeni terim yok.": "No new terms.",
    "Bağlantı": "Connection",
    "İptal": "Cancellation",
    "Yerel panel yanıt vermedi.": "The local dashboard did not respond.",
    "Yalnız .txt dosyası seçilebilir": "Only a .txt file can be selected",
    "TXT dosyası en fazla 1 MiB olabilir": "The TXT file can be at most 1 MiB",
    "TXT dosyası okunamadı": "The TXT file could not be read",
    "CCache dosyası seçilmelidir.": "Select a CCache file.",
    "Yalnız .ccache uzantılı dosya seçilebilir.": "Only a .ccache file can be selected.",
    "CCache dosyası boş olamaz.": "The CCache file cannot be empty.",
    "CCache dosyası en fazla 1 MiB olabilir.": "The CCache file can be at most 1 MiB.",
    "CCache dosyası okunamadı.": "The CCache file could not be read.",
  },
};

function uiText(value) {
  if (currentLanguage !== "en") return value;
  return LANGUAGE_TEXT.en[value] ?? DETAIL_LABELS[value] ?? value;
}

function numberLocale() {
  return currentLanguage === "en" ? "en-US" : "tr-TR";
}

function applyLanguage(language) {
  const dictionary = LANGUAGE_TEXT[language];
  if (!dictionary) return;
  document.documentElement.lang = language;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const translated = dictionary[node.nodeValue.trim()];
    if (translated) node.nodeValue = node.nodeValue.replace(node.nodeValue.trim(), translated);
  }
  for (const attribute of ["placeholder", "aria-label", "title"]) {
    for (const element of document.querySelectorAll(`[${attribute}]`)) {
      const value = element.getAttribute(attribute);
      if (dictionary[value]) {
        element.setAttribute(attribute, dictionary[value]);
      }
    }
  }
}

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

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  const raw = String(value);
  return localizedMap(STATUS_LABELS, EN_STATUS_LABELS, raw.toLowerCase()) ?? raw;
}

function findingLabel(value, labels) {
  if (value === null || value === undefined || value === "") return "—";
  const raw = String(value);
  if (currentLanguage === "en") {
    const english = labels === FINDING_METHOD_LABELS
      ? {wordlist: "Wordlist match", pattern: "Pattern match"}
      : {"secret-assignment": "Secret assignment"};
    return english[raw.toLowerCase()] ?? labels[raw.toLowerCase()] ?? raw;
  }
  return labels[raw.toLowerCase()] ?? raw;
}

function confidenceLabel(value) {
  const level = displayValue(value);
  const explanations = currentLanguage === "en"
    ? {
        High: "Strong, specific credential pattern.",
        Medium: "Suspicious pattern; verify it in context.",
        Low: "Weak signal; may be a false positive.",
      }
    : {
        Yüksek: "Güçlü ve belirgin credential kalıbı.",
        Orta: "Şüpheli kalıp; bağlamla doğrulanmalı.",
        Düşük: "Zayıf sinyal; yanlış eşleşme olabilir.",
      };
  return explanations[level] ? `${level} · ${explanations[level]}` : level;
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
    ["Hata ayrıntısı", targetErrorDetail(record) ?? record.detail],
  ]);
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
  signalLabel.textContent = uiText("Eşleşme");
  const signalValue = document.createElement("strong");
  signalValue.className = "finding-signal-value";
  signalValue.textContent = displayValue(record.term);
  signal.append(signalLabel, signalValue);

  const context = document.createElement("section");
  context.className = "finding-context";
  const contextLabel = document.createElement("span");
  contextLabel.className = "finding-context-label";
  contextLabel.textContent = uiText("Satır içeriği");
  const line = document.createElement("code");
  appendHighlightedText(line, record.fullLine, record.term);
  context.append(contextLabel, line);

  const metadata = detailList([
    ["Hedef", record.target, "detail-code"],
    ["Share", record.share, "detail-code"],
    ["Satır no", record.lineNumber, "detail-code"],
    ["Yöntem", findingLabel(record.method, FINDING_METHOD_LABELS)],
    ["Kural", findingLabel(record.ruleId, FINDING_RULE_LABELS)],
    ["Kategori", currentLanguage === "en"
      ? EN_CATEGORY_LABELS[record.category] ?? record.category
      : record.category],
    ["Güven", confidenceLabel(record.confidence)],
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

  for (const [kind, records] of orderedInventoryKinds(kinds)) {
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
    ["target", "share", "path", "type", "status", "size", "detail"],
  ));
  if (!visibleRecords.some(([key]) => key === selectedInventoryKey)) {
    selectedInventoryKey = visibleRecords[0]?.[0] ?? null;
    if (visibleRecords[0]) renderInventoryDetail(visibleRecords[0][1]);
    else setSelectionPlaceholder(inventorySelectionDetail, "Ayrıntı için bir kayıt seç.");
  }
  const groups = inventorySections(visibleRecords);
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
      const shareCount = document.createElement("span");
      shareCount.className = "result-group-count";
      const shareRecordCount = nestedInventoryCount(kinds);
      shareCount.textContent = currentLanguage === "en"
        ? `${shareRecordCount} entries`
        : `${shareRecordCount} kayıt`;
      shareSummary.append(shareLabel, shareCount);
      shareGroup.append(shareSummary);
      shareGroup.append(inventoryTable(kinds));
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
        row.append(textCell(
          findingLabel(record.method, FINDING_METHOD_LABELS),
          `status-value ${statusTone(record.method)}`,
        ));
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
  findingsVisibleCount.textContent = currentLanguage === "en"
    ? `${visibleRecords.length.toLocaleString(numberLocale())} findings`
    : `${visibleRecords.length.toLocaleString(numberLocale())} bulgu`;
  findingsTabCount.textContent = findingStore.size.toLocaleString(numberLocale());
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
  controls.count.textContent = currentLanguage === "en"
    ? `${resolvedCount.toLocaleString(numberLocale())} entries`
    : `${resolvedCount.toLocaleString(numberLocale())} kayıt`;
}

function setWordlistStatus(kind, message, tone = "") {
  const status = WORDLIST_EDITORS[kind].status;
  status.textContent = uiText(message);
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
      throw new CredentialInputError(uiText("Yalnız .txt dosyası seçilebilir"));
    }
    if (file.size > WORDLIST_MAX_BYTES) {
      throw new CredentialInputError(uiText("TXT dosyası en fazla 1 MiB olabilir"));
    }
    controls.editor.value = await file.text();
    setWordlistCount(kind);
    setWordlistStatus(kind, "İçe aktarıldı · kaydedilmedi", "is-ok");
  } catch (error) {
    const message = error instanceof CredentialInputError
      ? error.message
      : uiText("TXT dosyası okunamadı");
    setWordlistStatus(kind, message, "is-error");
  } finally {
    controls.file.value = "";
  }
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
  return credentialIsValid();
}

function storedHistory() {
  try {
    const value = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    if (!Array.isArray(value)) return [];
    const seen = new Set();
    const unique = value.filter((item) => {
      const key = item?.scan_id ?? `${item?.targets}|${item?.finished_at}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    if (unique.length !== value.length) {
      writeHistory(unique);
    }
    return unique;
  } catch (_error) {
    return [];
  }
}

function historyItemKey(item) {
  return item?.scan_id ?? `${item?.targets ?? ""}|${item?.finished_at ?? ""}`;
}

function writeHistory(history) {
  const candidate = history.slice(0, 20);
  while (candidate.length > 0) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(candidate));
      return true;
    } catch (_error) {
      if (candidate.length > 1) {
        candidate.pop();
        continue;
      }
      const summaryOnly = [{
        ...candidate[0],
        targets_snapshot: [],
        inventory_items: [],
        finding_items: [],
        history_incomplete: true,
      }];
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(summaryOnly));
      } catch (_ignored) {
        return false;
      }
      return false;
    }
  }
  try {
    localStorage.setItem(HISTORY_KEY, "[]");
  } catch (_error) {
    return false;
  }
  return true;
}

function renderHistory() {
  const history = storedHistory();
  historyTabCount.textContent = history.length;
  scanHistory.replaceChildren();
  if (history.length === 0) {
    const empty = document.createElement("p");
    empty.className = "group-empty-state";
    empty.textContent = uiText("Henüz kayıtlı tarama yok.");
    scanHistory.append(empty);
    return;
  }
  for (const item of history) {
    const row = document.createElement("div");
    row.className = "history-item";
    const title = document.createElement("strong");
    title.className = "history-item-title";
    title.textContent = item.name || item.targets || "Hedefler";
    const summary = document.createElement("span");
    summary.className = "history-item-summary";
    const rawStoredStatus = String(item.status ?? "completed").toLowerCase();
    const storedStatus = rawStoredStatus === "tamamlandı" ? "completed" : rawStoredStatus;
    const status = localizedMap(SCAN_STATUS_LABELS, EN_SCAN_STATUS_LABELS, storedStatus)
      ?? item.status;
    const parsedDate = Date.parse(item.finished_at);
    const finishedAt = Number.isNaN(parsedDate)
      ? item.finished_at
      : new Date(parsedDate).toLocaleString(numberLocale());
    summary.textContent = `${status} · ${finishedAt}`;
    const counts = document.createElement("span");
    counts.className = "history-item-counts";
    const credential = item.credential ?? {};
    const identity = credential.username || uiText("Kullanıcı yok");
    const domain = credential.domain ? `${credential.domain}\\${identity}` : identity;
    const kind = credential.kind === "nt_hash"
      ? "NT hash"
      : credential.kind === "ccache" ? "CCache" : uiText("Parola");
    const auth = credential.auth_mode ? ` · ${credential.auth_mode}` : "";
    counts.textContent = currentLanguage === "en"
      ? `${domain} · ${kind}${auth} · ${item.findings} findings · ${item.inventory} inventory entries`
      : `${domain} · ${kind}${auth} · ${item.findings} bulgu · ${item.inventory} envanter`;
    const view = document.createElement("button");
    view.type = "button";
    view.className = "secondary-button";
    view.textContent = uiText("Görüntüle");
    view.addEventListener("click", () => loadHistoryItem(item));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "secondary-button history-delete";
    remove.textContent = uiText("Sil");
    remove.addEventListener("click", () => deleteHistoryItem(item));
    row.append(title, summary, counts, view, remove);
    if (item.history_incomplete) {
      const warning = document.createElement("span");
      warning.className = "history-item-warning";
      warning.textContent = currentLanguage === "en"
        ? "Details could not be retained because browser storage is full."
        : "Tarayıcı depolama alanı dolduğu için ayrıntılar saklanamadı.";
      row.append(warning);
    }
    scanHistory.append(row);
  }
}

function deleteHistoryItem(item) {
  if (!window.confirm(uiText("Bu tarama geçmişten silinsin mi?"))) return;
  const itemKey = historyItemKey(item);
  const history = storedHistory().filter((entry) => historyItemKey(entry) !== itemKey);
  writeHistory(history);
  renderHistory();
}

function loadHistoryItem(item) {
  replaceTargets(item.targets_snapshot ?? []);
  replaceInventory(item.inventory_items ?? []);
  replaceFindings(item.finding_items ?? []);
  activateResultTab("findings");
}

function saveCompletedScan(state) {
  if (state.status !== "completed" || !state.scan_id) return;
  const history = storedHistory();
  const existing = history.find((item) => item.scan_id === state.scan_id);
  const snapshot = {
    targets_snapshot: [...targetStore.values()],
    inventory_items: [...inventoryStore.values()],
    finding_items: [...findingStore.values()],
  };
  if (existing) {
    const unchanged = JSON.stringify({
      targets_snapshot: existing.targets_snapshot ?? [],
      inventory_items: existing.inventory_items ?? [],
      finding_items: existing.finding_items ?? [],
    }) === JSON.stringify(snapshot);
    if (unchanged) return;
    Object.assign(existing, {
      findings: state.finding_count ?? findingStore.size,
      inventory: state.inventory_count ?? inventoryStore.size,
      ...snapshot,
    });
    writeHistory(history);
    renderHistory();
    return;
  }
  history.unshift({
    scan_id: state.scan_id,
    name: scanName.value.trim() || targets.value.trim() || "Hedefler",
    targets: targets.value.trim() || "Hedefler",
    credential: {
      domain: credentialDomain.value.trim() || null,
      username: credentialUsername.value.trim() || null,
      kind: credentialKind.value,
      auth_mode: authMode.value,
    },
    status: "completed",
    findings: state.finding_count ?? findingStore.size,
    inventory: state.inventory_count ?? inventoryStore.size,
    ...snapshot,
    finished_at: new Date().toISOString(),
  });
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
      return;
    }

    targetStore.clear();
    selectedTargetKey = null;
    setSelectionPlaceholder(targetSelectionDetail, "Ayrıntı için bir hedef seç.");
    renderTargetRows("Hedef sonuçları bekleniyor.");
    clearResults();
    activateResultTab("targets");
    cancelScanButton.disabled = false;
    await refreshSnapshot();
  } catch (error) {
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
languageSelect.value = currentLanguage;
if (currentLanguage === "en") applyLanguage(currentLanguage);
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

exportResultsButton.addEventListener("click", exportResults);
renderHistory();
languageSelect.addEventListener("change", () => {
  localStorage.setItem(LANGUAGE_KEY, languageSelect.value);
  window.location.reload();
});
