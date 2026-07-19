"use strict";

import {
  EN_SCAN_STATUS_LABELS,
  SCAN_STATUS_LABELS,
  currentLanguage,
  localizedMap,
  numberLocale,
  uiText,
} from "./app-i18n.js";

const historyDeleteDialog = document.querySelector("#history-delete-dialog");
const closeHistoryDeleteButton = document.querySelector("#close-history-delete");
const cancelHistoryDeleteButton = document.querySelector("#cancel-history-delete");
const confirmHistoryDeleteButton = document.querySelector("#confirm-history-delete");
const historyDeleteName = document.querySelector("#history-delete-name");
const historyDeleteMeta = document.querySelector("#history-delete-meta");
const historyTabCount = document.querySelector("#history-tab-count");
const scanHistory = document.querySelector("#scan-history");
const historySelectionDetail = document.querySelector("#history-selection-detail");

const HISTORY_KEY = "nordis.scan-history.v1";

let pendingHistoryDeleteKey = null;
let selectedHistoryKey = null;
let configured = false;

let activateResultTab;
let clearContents;
let detailList;
let detectionRulePackLabel;
let displayValue;
let formatFileSize;
let replaceFindings;
let replaceIdentityAccess;
let replaceInventory;
let replaceTargets;
let setSelectionPlaceholder;

function configureHistory(dependencies) {
  if (configured) return;
  ({
    activateResultTab,
    clearContents,
    detailList,
    detectionRulePackLabel,
    displayValue,
    formatFileSize,
    replaceFindings,
    replaceIdentityAccess,
    replaceInventory,
    replaceTargets,
    setSelectionPlaceholder,
  } = dependencies);
  closeHistoryDeleteButton.addEventListener("click", closeHistoryDeleteDialog);
  cancelHistoryDeleteButton.addEventListener("click", closeHistoryDeleteDialog);
  confirmHistoryDeleteButton.addEventListener("click", confirmHistoryItemDelete);
  historyDeleteDialog.addEventListener("close", () => {
    pendingHistoryDeleteKey = null;
  });
  historyDeleteDialog.addEventListener("click", (event) => {
    if (event.target === historyDeleteDialog) closeHistoryDeleteDialog();
  });
  configured = true;
}

function setSelectedHistoryKey(key) {
  selectedHistoryKey = key;
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

function historyFinishedAt(item) {
  const parsedDate = Date.parse(item.finished_at);
  return Number.isNaN(parsedDate)
    ? displayValue(item.finished_at)
    : new Date(parsedDate).toLocaleString(numberLocale());
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
        identity_access: null,
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

function credentialKindLabel(kind) {
  if (kind === "password") return uiText("Parola");
  if (kind === "nt_hash") return "NT hash";
  if (kind === "ccache") return "CCache";
  return displayValue(kind);
}

function authModeLabel(mode) {
  const labels = {
    auto: "Auto (Önerilen)",
    kerberos_only: "Yalnız Kerberos",
    ntlm_only: "Yalnız NTLM",
  };
  return labels[mode] ? uiText(labels[mode]) : displayValue(mode);
}

function retainedHistoryValue(value) {
  return value === null || value === undefined
    ? uiText("Bu kayıtta saklanmadı.")
    : value;
}

function historyDetailSection(title, fields) {
  const section = document.createElement("section");
  section.className = "history-detail-section";
  const heading = document.createElement("h4");
  heading.textContent = uiText(title);
  section.append(heading, detailList(fields));
  return section;
}

function appendHistorySecret(list, label, value) {
  const group = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = uiText(label);

  if (typeof value !== "string" || value === "") {
    description.textContent = uiText("Bu kayıtta saklanmadı.");
  } else {
    const secret = document.createElement("code");
    secret.className = "history-secret-code";
    secret.textContent = "••••••••••••";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "secondary-button history-secret-toggle";
    toggle.textContent = uiText("Göster");
    toggle.setAttribute("aria-pressed", "false");
    toggle.addEventListener("click", () => {
      const visible = toggle.getAttribute("aria-pressed") !== "true";
      toggle.setAttribute("aria-pressed", String(visible));
      toggle.textContent = uiText(visible ? "Gizle" : "Göster");
      secret.textContent = visible ? value : "••••••••••••";
    });
    description.className = "history-secret-value";
    description.append(secret, toggle);
  }

  group.append(term, description);
  list.append(group);
}

function renderHistoryDetail(item) {
  const credential = item.credential ?? {};
  const search = item.search;
  const searchRetained = search !== null && search !== undefined;
  const heading = document.createElement("h3");
  heading.className = "detail-heading";
  heading.textContent = item.name || item.targets || uiText("Hedefler");

  const counts = document.createElement("p");
  counts.className = "history-detail-meta";
  counts.textContent = currentLanguage === "en"
    ? `${historyFinishedAt(item)} · ${item.findings ?? 0} findings · ${item.inventory ?? 0} inventory entries`
    : `${historyFinishedAt(item)} · ${item.findings ?? 0} bulgu · ${item.inventory ?? 0} envanter`;

  const targetList = item.targets || (Array.isArray(item.target_list)
    ? item.target_list.join("\n")
    : item.targets);
  const legacyWriteAccess = item.test_write_access ?? false;
  const scanSection = historyDetailSection("Hedefler", [
    ["Tarama adı", displayValue(item.name), "detail-code"],
    ["Hedef listesi", retainedHistoryValue(targetList), "detail-code"],
    ["SMB yazma testi", uiText(
      (item.test_smb_write_access ?? legacyWriteAccess) ? "Dahil edildi" : "Dahil edilmedi",
    )],
    ["AD yazma testi", uiText(
      (item.test_ad_write_access ?? legacyWriteAccess) ? "Dahil edildi" : "Dahil edilmedi",
    )],
  ]);

  const credentialSection = historyDetailSection("Kimlik bilgisi", [
    ["Domain", displayValue(credential.domain), "detail-code"],
    ["Kullanıcı", displayValue(credential.username), "detail-code"],
    ["Kimlik türü", credentialKindLabel(credential.kind)],
    ["Kimlik doğrulama modu", authModeLabel(credential.auth_mode)],
  ]);
  const credentialList = credentialSection.querySelector(".detail-list");
  if (credential.kind === "password") {
    appendHistorySecret(credentialList, "Girilen parola", credential.password);
  } else if (credential.kind === "nt_hash") {
    appendHistorySecret(credentialList, "Girilen NT hash", credential.nt_hash);
  } else if (credential.kind === "ccache") {
    credentialList.append(...detailList([
      ["CCache dosya adı", retainedHistoryValue(credential.ccache_name), "detail-code"],
      ["CCache dosya boyutu", credential.ccache_size === null || credential.ccache_size === undefined
        ? uiText("Bu kayıtta saklanmadı.")
        : formatFileSize(credential.ccache_size)],
      ["Dosya yolu", uiText("Tarayıcı tam dosya yolunu paylaşmaz.")],
    ]).children);
  }

  const terms = typeof search?.additional_terms_input === "string"
    ? search.additional_terms_input || "—"
    : Array.isArray(search?.additional_terms)
      ? search.additional_terms.join("\n") || "—"
      : uiText("Bu kayıtta saklanmadı.");
  const retainedRulePacks = !searchRetained
    ? uiText("Bu kayıtta saklanmadı.")
    : !search.detect_patterns
      ? uiText("Dahil edilmedi")
      : Array.isArray(search.rule_packs)
        ? search.rule_packs.map(detectionRulePackLabel).join(", ") || "—"
        : uiText("Tümü");
  const searchSection = historyDetailSection("İçerik arama", [
    ["Özel terimler", terms, "detail-code"],
    ["Veri kalıpları", !searchRetained
      ? uiText("Bu kayıtta saklanmadı.")
      : uiText(search.detect_patterns ? "Dahil edildi" : "Dahil edilmedi")],
    ["Tespit kuralı paketleri", retainedRulePacks],
  ]);

  historySelectionDetail.replaceChildren(
    heading,
    counts,
    scanSection,
    credentialSection,
    searchSection,
  );
}

function selectHistoryItem(item) {
  selectedHistoryKey = historyItemKey(item);
  renderHistoryDetail(item);
  for (const row of scanHistory.querySelectorAll(".history-item")) {
    row.classList.toggle("is-selected", row.dataset.historyKey === selectedHistoryKey);
  }
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
    selectedHistoryKey = null;
    setSelectionPlaceholder(historySelectionDetail, "Girdileri görmek için bir tarama seç.");
    return;
  }
  for (const item of history) {
    const row = document.createElement("div");
    row.className = "history-item";
    row.dataset.historyKey = historyItemKey(item);
    row.classList.toggle("is-selected", row.dataset.historyKey === selectedHistoryKey);
    const selection = document.createElement("button");
    selection.type = "button";
    selection.className = "history-item-selection";
    const title = document.createElement("strong");
    title.className = "history-item-title";
    title.textContent = item.name || item.targets || "Hedefler";
    const summary = document.createElement("span");
    summary.className = "history-item-summary";
    const rawStoredStatus = String(item.status ?? "completed").toLowerCase();
    const storedStatus = rawStoredStatus === "tamamlandı" ? "completed" : rawStoredStatus;
    const status = localizedMap(SCAN_STATUS_LABELS, EN_SCAN_STATUS_LABELS, storedStatus)
      ?? item.status;
    const finishedAt = historyFinishedAt(item);
    summary.textContent = `${status} · ${finishedAt}`;
    const counts = document.createElement("span");
    counts.className = "history-item-counts";
    const credential = item.credential ?? {};
    const identity = credential.username || uiText("Kullanıcı yok");
    const domain = credential.domain ? `${credential.domain}\\${identity}` : identity;
    const kind = credentialKindLabel(credential.kind);
    const auth = credential.auth_mode ? ` · ${authModeLabel(credential.auth_mode)}` : "";
    counts.textContent = currentLanguage === "en"
      ? `${domain} · ${kind}${auth} · ${item.findings} findings · ${item.inventory} inventory entries`
      : `${domain} · ${kind}${auth} · ${item.findings} bulgu · ${item.inventory} envanter`;
    selection.setAttribute(
      "aria-label",
      `${uiText("Tarama ayarlarını göster")}: ${title.textContent}`,
    );
    selection.addEventListener("click", () => selectHistoryItem(item));
    selection.append(title, summary, counts);
    const view = document.createElement("button");
    view.type = "button";
    view.className = "secondary-button";
    view.textContent = uiText("Sonuçları aç");
    view.addEventListener("click", () => loadHistoryItem(item));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "secondary-button history-delete";
    remove.textContent = uiText("Sil");
    remove.addEventListener("click", () => deleteHistoryItem(item));
    row.append(selection, view, remove);
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
  const selected = history.find((item) => historyItemKey(item) === selectedHistoryKey);
  if (selected) {
    renderHistoryDetail(selected);
  } else {
    selectedHistoryKey = null;
    setSelectionPlaceholder(historySelectionDetail, "Girdileri görmek için bir tarama seç.");
  }
}

function deleteHistoryItem(item) {
  pendingHistoryDeleteKey = historyItemKey(item);
  historyDeleteName.textContent = item.name || item.targets || uiText("Hedefler");
  const findings = Number(item.findings ?? 0).toLocaleString(numberLocale());
  const inventory = Number(item.inventory ?? 0).toLocaleString(numberLocale());
  historyDeleteMeta.textContent = currentLanguage === "en"
    ? `${historyFinishedAt(item)} · ${findings} findings · ${inventory} inventory entries`
    : `${historyFinishedAt(item)} · ${findings} bulgu · ${inventory} envanter`;
  historyDeleteDialog.showModal();
}

function closeHistoryDeleteDialog() {
  historyDeleteDialog.close();
}

function confirmHistoryItemDelete() {
  if (pendingHistoryDeleteKey === null) return;
  const itemKey = pendingHistoryDeleteKey;
  const history = storedHistory().filter((entry) => historyItemKey(entry) !== itemKey);
  if (selectedHistoryKey === itemKey) selectedHistoryKey = null;
  writeHistory(history);
  historyDeleteDialog.close();
  renderHistory();
}

function loadHistoryItem(item) {
  selectHistoryItem(item);
  replaceTargets(item.targets_snapshot ?? []);
  replaceInventory(item.inventory_items ?? []);
  replaceFindings(item.finding_items ?? []);
  replaceIdentityAccess(item.identity_access ?? null);
  clearContents(currentLanguage === "en"
    ? "Content preview and download are available only for the live scan."
    : "İçerik önizleme ve indirme yalnızca canlı taramada kullanılabilir.");
  activateResultTab("findings");
}

export {
  configureHistory,
  renderHistory,
  setSelectedHistoryKey,
  storedHistory,
  writeHistory,
};
