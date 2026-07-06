"use strict";

import {currentLanguage, numberLocale} from "./app-i18n.js";

const contentFilter = document.querySelector("#content-filter");
const contentSourceFilter = document.querySelector("#content-source-filter");
const contentFlaggedFilter = document.querySelector("#content-flagged-filter");
const contentVisibleCount = document.querySelector("#content-visible-count");
const contentTabCount = document.querySelector("#content-tab-count");
const contentTableBody = document.querySelector("#content-table-body");
const contentSelectionDetail = document.querySelector("#content-selection-detail");

const contentStore = new Map();
let selectedContentId = null;
let previewSequence = 0;
let refreshTimer = null;

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

function formatSize(value) {
  const size = Number(value);
  if (!Number.isFinite(size) || size < 0) return "—";
  if (size < 1024) return `${size} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let amount = size;
  let unitIndex = -1;
  do {
    amount /= 1024;
    unitIndex += 1;
  } while (amount >= 1024 && unitIndex < units.length - 1);
  return `${amount.toLocaleString(numberLocale(), {maximumFractionDigits: 1})} ${units[unitIndex]}`;
}

function sourceLabel(source) {
  if (source === "ldap") return "LDAP";
  return "SMB";
}

function typeLabel(type) {
  const labels = currentLanguage === "en"
    ? {
      user: "User", computer: "Computer", group: "Group", gpo: "GPO",
      organizational_unit: "OU", contact: "Contact", domain: "Domain",
      container: "Container", directory_object: "Directory object",
    }
    : {
      user: "Kullanıcı", computer: "Bilgisayar", group: "Grup", gpo: "GPO",
      organizational_unit: "OU", contact: "Contact", domain: "Domain",
      container: "Container", directory_object: "Directory nesnesi",
    };
  return labels[String(type ?? "").toLowerCase()] ?? displayValue(type);
}

function contentRecord(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  if (typeof raw.id !== "string" || !["smb", "ldap"].includes(raw.source)) return null;
  const signals = Array.isArray(raw.signals)
    ? raw.signals.filter((item) => item && typeof item === "object" && !Array.isArray(item))
    : [];
  return {
    id: raw.id,
    source: raw.source,
    title: raw.title,
    target: raw.target,
    share: raw.share,
    path: raw.path,
    distinguishedName: raw.distinguished_name,
    subject: raw.subject,
    subjectType: raw.subject_type,
    attribute: raw.attribute,
    size: raw.size,
    flagged: raw.flagged === true,
    signals,
    previewAvailable: raw.preview_available === true,
    downloadAvailable: raw.download_available === true,
  };
}

function contentLocation(record) {
  if (record.source === "ldap") {
    return `${displayValue(record.attribute)} · ${displayValue(record.distinguishedName)}`;
  }
  return `\\\\${displayValue(record.target)}\\${displayValue(record.share)}\\${displayValue(record.path)}`;
}

function contentSearchText(record) {
  return [
    record.source,
    record.title,
    record.target,
    record.share,
    record.path,
    record.distinguishedName,
    record.subject,
    record.subjectType,
    record.attribute,
    ...record.signals.flatMap((signal) => [signal.title, signal.category, signal.rule_id]),
  ].map(displayValue).join(" ").toLocaleLowerCase(currentLanguage === "en" ? "en-US" : "tr-TR");
}

function visibleContents() {
  const query = contentFilter.value.trim().toLocaleLowerCase(
    currentLanguage === "en" ? "en-US" : "tr-TR",
  );
  const source = contentSourceFilter.value;
  return [...contentStore.values()].filter((record) => (
    (source === "all" || record.source === source)
    && (!contentFlaggedFilter.checked || record.flagged)
    && (!query || contentSearchText(record).includes(query))
  ));
}

function marker() {
  const value = document.createElement("span");
  value.className = "content-review-marker";
  value.textContent = currentLanguage === "en" ? "Review" : "İncele";
  return value;
}

function textCell(value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = displayValue(value);
  return cell;
}

function bindRow(row, record) {
  const select = () => {
    selectedContentId = record.id;
    renderContents();
    renderContentDetail(record);
  };
  row.tabIndex = 0;
  row.classList.toggle("is-selected", selectedContentId === record.id);
  row.setAttribute("aria-selected", String(selectedContentId === record.id));
  row.addEventListener("click", select);
  row.addEventListener("keydown", (event) => {
    if (!['Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    select();
  });
}

function renderContents() {
  const records = visibleContents();
  if (!records.some((record) => record.id === selectedContentId)) {
    selectedContentId = records[0]?.id ?? null;
    if (records[0]) renderContentDetail(records[0]);
    else renderEmptyDetail();
  }
  contentTableBody.replaceChildren();
  for (const record of records) {
    const row = document.createElement("tr");
    row.append(textCell(sourceLabel(record.source), "content-source-value"));
    row.append(textCell(record.title, "content-title-value"));
    row.append(textCell(
      record.source === "ldap" ? record.attribute : contentLocation(record),
      "content-location-value",
    ));
    row.append(textCell(formatSize(record.size)));
    const signalCell = document.createElement("td");
    if (record.flagged) signalCell.append(marker());
    else signalCell.textContent = "—";
    row.append(signalCell);
    bindRow(row, record);
    contentTableBody.append(row);
  }
  if (records.length === 0) {
    const row = document.createElement("tr");
    row.className = "table-empty-row";
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = contentStore.size === 0
      ? currentLanguage === "en" ? "No live content yet." : "Henüz canlı içerik yok."
      : currentLanguage === "en" ? "No content matches the filters." : "Filtreyle eşleşen içerik yok.";
    row.append(cell);
    contentTableBody.append(row);
  }
  contentVisibleCount.textContent = currentLanguage === "en"
    ? `${records.length.toLocaleString(numberLocale())} entries`
    : `${records.length.toLocaleString(numberLocale())} kayıt`;
  contentTabCount.textContent = contentStore.size.toLocaleString(numberLocale());
}

function detailRow(labelText, valueText, code = false) {
  const row = document.createElement("div");
  const label = document.createElement("dt");
  label.textContent = labelText;
  const value = document.createElement("dd");
  value.textContent = displayValue(valueText);
  if (code) value.className = "detail-code";
  row.append(label, value);
  return row;
}

function renderContentDetail(record) {
  previewSequence += 1;
  const sequence = previewSequence;
  const header = document.createElement("header");
  header.className = "content-detail-header";
  const heading = document.createElement("h3");
  heading.className = "detail-heading";
  heading.textContent = displayValue(record.title);
  header.append(heading);

  const actions = document.createElement("div");
  actions.className = "content-detail-actions";
  if (record.downloadAvailable) {
    const download = document.createElement("a");
    download.className = "secondary-button content-download";
    download.href = `/contents/${encodeURIComponent(record.id)}/download`;
    download.textContent = currentLanguage === "en" ? "Download" : "İndir";
    actions.append(download);
  }

  const metadata = document.createElement("dl");
  metadata.className = "detail-list content-metadata";
  metadata.append(
    detailRow(currentLanguage === "en" ? "Source" : "Kaynak", sourceLabel(record.source)),
    detailRow(
      currentLanguage === "en" ? "Location" : "Konum",
      contentLocation(record),
      true,
    ),
    detailRow(currentLanguage === "en" ? "Size" : "Boyut", formatSize(record.size)),
  );
  if (record.source === "ldap") {
    metadata.append(
      detailRow(currentLanguage === "en" ? "Object type" : "Nesne türü", typeLabel(record.subjectType)),
      detailRow(currentLanguage === "en" ? "Attribute" : "Alan", record.attribute, true),
    );
  }

  const preview = document.createElement("section");
  preview.className = "content-preview";
  const previewHeading = document.createElement("div");
  previewHeading.className = "content-preview-heading";
  previewHeading.textContent = currentLanguage === "en" ? "Content" : "İçerik";
  const pre = document.createElement("pre");
  const code = document.createElement("code");
  code.textContent = record.previewAvailable
    ? currentLanguage === "en" ? "Loading…" : "Yükleniyor…"
    : currentLanguage === "en"
      ? "Preview is unavailable for this content; download it to inspect."
      : "Bu içerik panelde önizlenemiyor; incelemek için indirebilirsin.";
  pre.append(code);
  preview.append(previewHeading, pre);

  const sections = [header];
  if (actions.childElementCount > 0) sections.push(actions);
  sections.push(metadata);
  sections.push(preview);
  contentSelectionDetail.replaceChildren(...sections);
  if (record.previewAvailable) loadPreview(record, code, sequence);
}

async function loadPreview(record, code, sequence) {
  try {
    const response = await fetch(`/contents/${encodeURIComponent(record.id)}/preview`, {
      cache: "no-store",
      credentials: "omit",
    });
    const payload = await response.json();
    if (sequence !== previewSequence || selectedContentId !== record.id) return;
    if (!response.ok) {
      code.textContent = payload?.error?.message
        ?? (currentLanguage === "en" ? "Content could not be opened." : "İçerik açılamadı.");
      return;
    }
    code.textContent = displayValue(payload.text);
    if (payload.truncated === true) {
      const note = document.createElement("p");
      note.className = "content-preview-note";
      note.textContent = currentLanguage === "en"
        ? "The preview is truncated; the download contains the complete file."
        : "Önizleme sınırlıdır; indirilen dosya tam içeriği içerir.";
      code.closest("section")?.append(note);
    }
  } catch (_error) {
    if (sequence === previewSequence && selectedContentId === record.id) {
      code.textContent = currentLanguage === "en"
        ? "The local panel did not return the content."
        : "Yerel panel içeriği döndürmedi.";
    }
  }
}

function renderEmptyDetail(message = null) {
  previewSequence += 1;
  const placeholder = document.createElement("p");
  placeholder.className = "selection-placeholder";
  placeholder.textContent = message ?? (currentLanguage === "en"
    ? "Select an entry to view its content."
    : "İçeriğini görmek için bir kayıt seç.");
  contentSelectionDetail.replaceChildren(placeholder);
}

function replaceContents(records) {
  contentStore.clear();
  for (const raw of records ?? []) {
    const record = contentRecord(raw);
    if (record) contentStore.set(record.id, record);
  }
  if (!contentStore.has(selectedContentId)) selectedContentId = null;
  renderContents();
}

function clearContents(message = null) {
  contentStore.clear();
  selectedContentId = null;
  renderContents();
  if (message) renderEmptyDetail(message);
}

async function refreshContents() {
  try {
    const records = [];
    let page = 1;
    while (true) {
      const response = await fetch(`/contents?page=${page}&page_size=500`, {
        cache: "no-store",
        credentials: "omit",
      });
      if (!response.ok) return false;
      const payload = await response.json();
      if (!Array.isArray(payload.items)) return false;
      records.push(...payload.items);
      if (page >= Number(payload.total_pages ?? 0)) break;
      page += 1;
    }
    replaceContents(records);
    return true;
  } catch (_error) {
    return false;
  }
}

function scheduleContentRefresh() {
  if (refreshTimer !== null) return;
  refreshTimer = window.setTimeout(async () => {
    refreshTimer = null;
    await refreshContents();
  }, 180);
}

contentFilter.addEventListener("input", renderContents);
contentSourceFilter.addEventListener("change", renderContents);
contentFlaggedFilter.addEventListener("change", renderContents);
renderContents();

export {
  clearContents,
  refreshContents,
  scheduleContentRefresh,
};
