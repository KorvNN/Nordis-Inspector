"use strict";

import {currentLanguage, numberLocale, uiText} from "./app-i18n.js";

const body = document.body;
const csrfToken = body.dataset.csrfToken;
const origin = body.dataset.origin;
const hashToolsNavigationCount = document.querySelector("#hash-tools-navigation-count");
const hashToolAvailability = document.querySelector("#hash-tool-availability");
const hashCandidateCount = document.querySelector("#hash-candidate-count");
const hashCandidateList = document.querySelector("#hash-candidate-list");
const hashSelectionSummary = document.querySelector("#hash-selection-summary");
const hashJobState = document.querySelector("#hash-job-state");
const hashToolSelect = document.querySelector("#hash-tool-select");
const hashRuntimeSelect = document.querySelector("#hash-runtime-select");
const hashWordlistFile = document.querySelector("#hash-wordlist-file");
const hashWordlistSummary = document.querySelector("#hash-wordlist-summary");
const startHashToolButton = document.querySelector("#start-hash-tool");
const cancelHashToolButton = document.querySelector("#cancel-hash-tool");
const hashToolMessage = document.querySelector("#hash-tool-message");
const hashToolResult = document.querySelector("#hash-tool-result");
const hashToolPlaintext = document.querySelector("#hash-tool-plaintext");

const HASH_WORDLIST_MAX_BYTES = 256 * 1024 * 1024;

class CredentialInputError extends Error {}

let selectedHashCandidateKey = null;
let hashWordlistUpload = null;
let hashWordlistName = "";
let hashWordlistUploading = false;
let hashToolsState = {tools: [], job: null, wordlist: null};
let hashToolsAvailabilityError = null;
let hashToolsRefreshTimer = null;
let scanActive = false;
let configured = false;

let displayValue;
let findingStore;
let formatFileSize;
let hashFormatLabel;
let hashJobLabel;
let mutationHeaders;

async function responsePayload(response) {
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

function configureHashTools(dependencies) {
  if (configured) return;
  ({
    displayValue,
    findingStore,
    formatFileSize,
    hashFormatLabel,
    hashJobLabel,
    mutationHeaders,
  } = dependencies);
  hashToolSelect.addEventListener("change", syncHashToolControls);
  hashWordlistFile.addEventListener("change", loadHashWordlist);
  startHashToolButton.addEventListener("click", startHashTool);
  cancelHashToolButton.addEventListener("click", cancelHashTool);
  configured = true;
}

function setHashScanActive(active) {
  scanActive = Boolean(active);
  syncHashToolControls();
}

function hashCandidateEntries() {
  const entries = [];
  for (const [recordKey, record] of findingStore) {
    for (const candidate of record.auditCandidates) {
      entries.push({
        key: `${recordKey}\u001e${candidate.id}`,
        record,
        candidate,
      });
    }
  }
  return entries;
}

function selectedHashCandidate() {
  return hashCandidateEntries().find((entry) => entry.key === selectedHashCandidateKey) ?? null;
}

function hashToolName(toolId) {
  return hashToolsState.tools.find((tool) => tool.id === toolId)?.name
    ?? ({hashcat: "Hashcat", john: "John the Ripper"}[toolId] ?? toolId);
}

function compatibleInstalledHashTools(entry) {
  if (!entry) return [];
  const installed = new Map(
    hashToolsState.tools
      .filter((tool) => tool.available)
      .map((tool) => [tool.id, tool]),
  );
  return entry.candidate.tools
    .filter((binding) => {
      const tool = installed.get(binding.id);
      return tool && (
        tool.formats === null
        || tool.formats.includes(String(binding.format).toLowerCase())
      );
    })
    .map((binding) => ({...installed.get(binding.id), bindingFormat: binding.format}));
}

function hashJobIsActive() {
  return ["running", "cancelling"].includes(hashToolsState.job?.status);
}

function renderHashCandidates() {
  const entries = hashCandidateEntries();
  if (!entries.some((entry) => entry.key === selectedHashCandidateKey)) {
    const jobCandidateId = hashToolsState.job?.candidate_id;
    selectedHashCandidateKey = entries.find(
      (entry) => entry.candidate.id === jobCandidateId,
    )?.key ?? entries[0]?.key ?? null;
  }
  const count = entries.length.toLocaleString(numberLocale());
  hashToolsNavigationCount.textContent = count;
  hashCandidateCount.textContent = count;
  hashCandidateList.replaceChildren();

  if (entries.length === 0) {
    const empty = document.createElement("p");
    empty.className = "hash-empty-state";
    empty.textContent = uiText("Uygun bulgu yok.");
    hashCandidateList.append(empty);
    renderHashSelection();
    return;
  }

  const jobActive = hashJobIsActive();
  for (const entry of entries) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "hash-candidate-row";
    row.classList.toggle("is-selected", entry.key === selectedHashCandidateKey);
    row.setAttribute("aria-pressed", String(entry.key === selectedHashCandidateKey));
    row.disabled = jobActive;

    const file = document.createElement("span");
    file.className = "hash-candidate-file";
    file.textContent = displayValue(entry.record.file);
    const format = document.createElement("span");
    format.className = "hash-candidate-format";
    format.textContent = hashFormatLabel(entry.candidate.format);
    const source = document.createElement("span");
    source.className = "hash-candidate-source";
    source.textContent = [entry.record.target, entry.record.share]
      .filter((value) => value !== null && value !== undefined && value !== "")
      .join(" · ") || "—";
    const tools = document.createElement("span");
    tools.className = "hash-candidate-tools";
    tools.textContent = entry.candidate.tools
      .map((binding) => hashToolName(binding.id))
      .join(" · ");
    row.append(file, format, source, tools);
    row.addEventListener("click", () => {
      selectedHashCandidateKey = entry.key;
      renderHashCandidates();
    });
    hashCandidateList.append(row);
  }
  renderHashSelection();
}

function renderHashSelection() {
  const entry = selectedHashCandidate();
  const previousTool = hashToolSelect.value;
  const compatibleTools = compatibleInstalledHashTools(entry);
  hashToolSelect.replaceChildren();
  if (compatibleTools.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = hashToolsAvailabilityError
      ? uiText("Araç durumu alınamadı.")
      : uiText("Kullanılabilir araç yok");
    hashToolSelect.append(option);
  } else {
    for (const tool of compatibleTools) {
      const option = document.createElement("option");
      option.value = tool.id;
      option.textContent = tool.id === "hashcat"
        ? `${tool.name} · -m ${tool.bindingFormat}`
        : `${tool.name} · --format=${tool.bindingFormat}`;
      hashToolSelect.append(option);
    }
    if (compatibleTools.some((tool) => tool.id === previousTool)) {
      hashToolSelect.value = previousTool;
    }
  }

  hashSelectionSummary.textContent = entry
    ? `${hashFormatLabel(entry.candidate.format)} · ${displayValue(entry.record.file)}`
    : uiText("Önce bir bulgu seç.");
  syncHashToolControls();
}

function syncHashToolControls() {
  const entry = selectedHashCandidate();
  const jobActive = hashJobIsActive();
  const toolAvailable = hashToolSelect.value !== "";
  hashToolSelect.disabled = jobActive || !entry || hashToolSelect.options.length === 0
    || !toolAvailable;
  hashRuntimeSelect.disabled = jobActive || hashWordlistUploading;
  hashWordlistFile.disabled = jobActive || scanActive || hashWordlistUploading;
  startHashToolButton.disabled = jobActive
    || scanActive
    || hashWordlistUploading
    || !entry
    || !toolAvailable
    || typeof hashWordlistUpload?.upload_id !== "string";
  cancelHashToolButton.disabled = !jobActive;
}

function renderHashToolAvailability() {
  hashToolAvailability.replaceChildren();
  if (hashToolsState.tools.length === 0) {
    const status = document.createElement("span");
    status.className = "hash-tool-checking";
    status.textContent = hashToolsAvailabilityError === "backend_unavailable"
      ? uiText("Hash Araçları backend’i bulunamadı. Uygulamayı yeniden başlat.")
      : hashToolsAvailabilityError
        ? uiText("Araç durumu alınamadı.")
        : uiText("Yerel araçlar kontrol ediliyor.");
    hashToolAvailability.append(status);
    return;
  }
  for (const tool of hashToolsState.tools) {
    const item = document.createElement("div");
    item.className = `hash-tool-availability-item ${
      tool.available ? "is-available" : "is-unavailable"
    }`;
    const name = document.createElement("strong");
    name.textContent = tool.name;
    const status = document.createElement("span");
    status.textContent = tool.available
      ? uiText("Kullanıma hazır")
      : tool.reason === "backend_unavailable"
        ? currentLanguage === "en" ? "Compute backend unavailable" : "Hesaplama backend’i yok"
        : tool.reason === "initialization_failed"
          ? currentLanguage === "en" ? "Could not initialize" : "Başlatılamıyor"
          : tool.reason === "format_catalog_unavailable"
            ? currentLanguage === "en" ? "Format catalog unavailable" : "Format kataloğu okunamadı"
            : tool.reason === "no_supported_formats"
              ? currentLanguage === "en" ? "No compatible formats" : "Uyumlu format yok"
        : uiText("Bulunamadı");
    item.append(name, status);
    hashToolAvailability.append(item);
  }
}

function hashToolErrorMessage(code) {
  const messages = currentLanguage === "en"
    ? {
      SCAN_IN_PROGRESS: "Stop the SMB scan before running a hash tool.",
      HASH_TOOL_IN_PROGRESS: "Another hash tool job is already running.",
      HASH_TOOL_NOT_RUNNING: "There is no running hash tool job.",
      TOOL_UNAVAILABLE: "The selected local tool is no longer available.",
      INVALID_TOOL: "Select an available local tool.",
      INCOMPATIBLE_TOOL: "The selected tool does not support this hash format.",
      INVALID_RUNTIME: "Select a supported time limit.",
      INVALID_WORDLIST: "The wordlist is invalid.",
      WORDLIST_SIZE_INVALID: "The wordlist cannot be empty.",
      WORDLIST_ENTRY_COUNT_INVALID: "The wordlist does not contain usable candidates.",
      WORDLIST_LINE_TOO_LONG: "A wordlist entry exceeds the 64 KiB safety limit.",
      WORDLIST_TOO_LARGE: "The wordlist exceeds the 256 MiB safety limit.",
      WORDLIST_NOT_FOUND: "Upload the wordlist again.",
      WORDLIST_UPLOAD_IN_PROGRESS: "A wordlist is already being uploaded.",
      WORDLIST_UPLOAD_FAILED: "The wordlist could not be uploaded.",
      INVALID_CANDIDATE: "Select a supported finding.",
      UNSUPPORTED_CANDIDATE: "The finding is no longer a supported hash candidate.",
      INVALID_REQUEST: "The request is invalid.",
      HASHCAT_FAILED: "Hashcat could not complete the job.",
      JOHN_FAILED: "John the Ripper could not complete the job.",
      TOOL_EXECUTION_FAILED: "The local tool could not be started.",
      FORMAT_MISMATCH: "The selected tool format is incompatible.",
    }
    : {
      SCAN_IN_PROGRESS: "Hash aracını çalıştırmadan önce SMB taramasını durdur.",
      HASH_TOOL_IN_PROGRESS: "Başka bir hash aracı işi zaten çalışıyor.",
      HASH_TOOL_NOT_RUNNING: "Çalışan bir hash aracı işi yok.",
      TOOL_UNAVAILABLE: "Seçilen yerel araç artık kullanılamıyor.",
      INVALID_TOOL: "Kullanılabilir bir yerel araç seç.",
      INCOMPATIBLE_TOOL: "Seçilen araç bu hash biçimini desteklemiyor.",
      INVALID_RUNTIME: "Desteklenen bir süre sınırı seç.",
      INVALID_WORDLIST: "Wordlist geçersiz.",
      WORDLIST_SIZE_INVALID: "Wordlist boş olamaz.",
      WORDLIST_ENTRY_COUNT_INVALID: "Wordlist kullanılabilir aday içermiyor.",
      WORDLIST_LINE_TOO_LONG: "Bir wordlist satırı 64 KiB güvenlik sınırını aşıyor.",
      WORDLIST_TOO_LARGE: "Wordlist 256 MiB güvenlik sınırını aşıyor.",
      WORDLIST_NOT_FOUND: "Wordlist dosyasını yeniden yükle.",
      WORDLIST_UPLOAD_IN_PROGRESS: "Başka bir wordlist yükleniyor.",
      WORDLIST_UPLOAD_FAILED: "Wordlist yüklenemedi.",
      INVALID_CANDIDATE: "Desteklenen bir bulgu seç.",
      UNSUPPORTED_CANDIDATE: "Bulgu artık desteklenen bir hash adayı değil.",
      INVALID_REQUEST: "İstek geçersiz.",
      HASHCAT_FAILED: "Hashcat işi tamamlayamadı.",
      JOHN_FAILED: "John the Ripper işi tamamlayamadı.",
      TOOL_EXECUTION_FAILED: "Yerel araç başlatılamadı.",
      FORMAT_MISMATCH: "Seçilen araç biçimi uyumsuz.",
    };
  return messages[String(code)]
    ?? (currentLanguage === "en" ? "The local job could not be completed." : "Yerel iş tamamlanamadı.");
}

function hashJobMessage(job) {
  if (!job) return "";
  const tool = hashToolName(job.tool_id);
  const format = hashFormatLabel(job.format);
  const seconds = Number(job.runtime_seconds ?? 0).toLocaleString(numberLocale());
  if (job.status === "running") {
    return currentLanguage === "en"
      ? `${tool} is running · ${format} · ${seconds} second limit.`
      : `${tool} çalışıyor · ${format} · ${seconds} saniye sınırı.`;
  }
  if (job.status === "cancelling") {
    return currentLanguage === "en" ? "Stopping the local job." : "Yerel iş durduruluyor.";
  }
  if (job.status === "cracked") {
    return currentLanguage === "en"
      ? "The wordlist contains the matching password."
      : "Wordlist içinde eşleşen parola bulundu.";
  }
  if (job.status === "exhausted") {
    return currentLanguage === "en"
      ? "No password in the wordlist matched this hash."
      : "Wordlist içindeki parolalar bu hash ile eşleşmedi.";
  }
  if (job.status === "timed_out") {
    return currentLanguage === "en"
      ? "The configured time limit was reached."
      : "Ayarlanan süre sınırına ulaşıldı.";
  }
  if (job.status === "cancelled") {
    return currentLanguage === "en" ? "The local job was stopped." : "Yerel iş durduruldu.";
  }
  if (job.status === "failed") return hashToolErrorMessage(job.error_code);
  return "";
}

function renderHashJob() {
  const retainedJob = hashToolsState.job;
  const selected = selectedHashCandidate();
  const job = retainedJob && selected && retainedJob.candidate_id !== selected.candidate.id
    ? null
    : retainedJob;
  const status = job?.status ?? "idle";
  hashJobState.textContent = hashJobLabel(status);
  const tone = status === "cracked"
    ? "is-ok"
    : ["running", "cancelling"].includes(status)
      ? "is-working"
      : status === "failed" ? "is-error" : "";
  hashJobState.className = `status-value${tone ? ` ${tone}` : ""}`;
  hashToolMessage.textContent = hashJobMessage(job);
  hashToolMessage.className = `hash-tool-message${
    status === "failed" ? " is-error" : status === "cracked" ? " is-ok" : ""
  }`;
  const showPlaintext = status === "cracked" && typeof job?.plaintext === "string";
  hashToolResult.hidden = !showPlaintext;
  hashToolPlaintext.textContent = showPlaintext ? job.plaintext : "";
  renderHashCandidates();
}

function normalizedHashToolsPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const tools = Array.isArray(payload.tools)
    ? payload.tools
      .filter((tool) => (
        tool
        && typeof tool === "object"
        && !Array.isArray(tool)
        && typeof tool.id === "string"
        && typeof tool.name === "string"
        && typeof tool.available === "boolean"
      ))
      .map((tool) => ({
        id: tool.id,
        name: tool.name,
        available: tool.available,
        reason: typeof tool.reason === "string" ? tool.reason : null,
        formats: Array.isArray(tool.formats)
          ? [...new Set(tool.formats
            .filter((format) => typeof format === "string" && format !== "")
            .map((format) => format.toLowerCase()))]
          : null,
      }))
    : [];
  const job = payload.job && typeof payload.job === "object" && !Array.isArray(payload.job)
    ? payload.job
    : null;
  const wordlist = (
    payload.wordlist
    && typeof payload.wordlist === "object"
    && !Array.isArray(payload.wordlist)
    && typeof payload.wordlist.upload_id === "string"
    && Number.isSafeInteger(payload.wordlist.size_bytes)
    && payload.wordlist.size_bytes > 0
    && Number.isSafeInteger(payload.wordlist.entry_count)
    && payload.wordlist.entry_count > 0
  )
    ? {
        upload_id: payload.wordlist.upload_id,
        size_bytes: payload.wordlist.size_bytes,
        entry_count: payload.wordlist.entry_count,
      }
    : null;
  return {tools, job, wordlist};
}

function renderHashWordlistSummary() {
  if (hashWordlistUploading) return;
  if (!hashWordlistUpload) {
    hashWordlistSummary.textContent = "—";
    return;
  }
  const name = hashWordlistName || uiText("Yüklenen wordlist");
  const entries = hashWordlistUpload.entry_count.toLocaleString(numberLocale());
  const entryLabel = currentLanguage === "en" ? "entries" : "kayıt";
  hashWordlistSummary.textContent = `${name} · ${formatFileSize(
    hashWordlistUpload.size_bytes,
  )} · ${entries} ${entryLabel}`;
}

function scheduleHashToolsRefresh() {
  if (hashToolsRefreshTimer !== null) window.clearTimeout(hashToolsRefreshTimer);
  hashToolsRefreshTimer = hashJobIsActive()
    ? window.setTimeout(() => void refreshHashTools(), 800)
    : null;
}

async function refreshHashTools() {
  try {
    const response = await fetch("/hash-tools", {cache: "no-store", credentials: "omit"});
    if (!response.ok) {
      throw new Error(response.status === 404 ? "backend_unavailable" : "request_failed");
    }
    const payload = normalizedHashToolsPayload(await responsePayload(response));
    if (!payload) throw new Error("invalid_hash_tools_payload");
    hashToolsState = payload;
    hashToolsAvailabilityError = null;
    if (!hashWordlistUploading) {
      if (!payload.wordlist) {
        hashWordlistUpload = null;
        hashWordlistName = "";
        hashWordlistFile.value = "";
      } else {
        if (hashWordlistUpload?.upload_id !== payload.wordlist.upload_id) {
          hashWordlistName = "";
        }
        hashWordlistUpload = payload.wordlist;
      }
      renderHashWordlistSummary();
    }
    renderHashToolAvailability();
    renderHashJob();
  } catch (error) {
    hashToolsState = {...hashToolsState, tools: []};
    hashToolsAvailabilityError = error instanceof Error ? error.message : "request_failed";
    renderHashToolAvailability();
    renderHashCandidates();
  } finally {
    scheduleHashToolsRefresh();
  }
}

function setHashToolMessage(message, tone = "") {
  hashToolMessage.textContent = message;
  hashToolMessage.className = `hash-tool-message${tone ? ` ${tone}` : ""}`;
}

async function loadHashWordlist() {
  const file = hashWordlistFile.files?.[0];
  if (!file) {
    renderHashWordlistSummary();
    syncHashToolControls();
    return;
  }
  const previousUpload = hashWordlistUpload;
  const previousName = hashWordlistName;
  try {
    if (!file.name.toLocaleLowerCase(numberLocale()).endsWith(".txt")) {
      throw new CredentialInputError(uiText("Yalnız .txt wordlist seçilebilir."));
    }
    if (file.size > HASH_WORDLIST_MAX_BYTES) {
      throw new CredentialInputError(uiText("Wordlist en fazla 256 MiB olabilir."));
    }
    if (file.size === 0) throw new CredentialInputError(uiText("Wordlist boş olamaz."));
    hashWordlistUploading = true;
    hashWordlistSummary.textContent = `${file.name} · ${formatFileSize(file.size)} · ${uiText(
      "Wordlist yükleniyor.",
    )}`;
    setHashToolMessage(uiText("Wordlist yükleniyor."));
    syncHashToolControls();

    const response = await fetch("/hash-tools/wordlist", {
      method: "PUT",
      credentials: "omit",
      cache: "no-store",
      headers: {
        "Content-Type": "application/octet-stream",
        "Origin": origin,
        "X-CSRF-Token": csrfToken,
      },
      body: file,
    });
    const rawPayload = await responsePayload(response);
    const payload = normalizedHashToolsPayload(rawPayload);
    if (!response.ok || !payload?.wordlist) {
      throw new CredentialInputError(hashToolErrorMessage(rawPayload?.error));
    }
    hashToolsState = payload;
    hashWordlistUpload = payload.wordlist;
    hashWordlistName = file.name;
    setHashToolMessage(uiText("Wordlist yüklendi."), "is-ok");
  } catch (error) {
    hashWordlistUpload = previousUpload;
    hashWordlistName = previousName;
    const message = error instanceof CredentialInputError
      ? error.message
      : uiText("Wordlist okunamadı.");
    setHashToolMessage(message, "is-error");
  } finally {
    hashWordlistUploading = false;
    hashWordlistFile.value = "";
    renderHashWordlistSummary();
    syncHashToolControls();
  }
}

async function startHashTool() {
  const entry = selectedHashCandidate();
  if (!entry) return;
  if (typeof hashWordlistUpload?.upload_id !== "string") {
    setHashToolMessage(uiText("Wordlist dosyası seç."), "is-error");
    return;
  }
  setHashToolMessage(uiText("İşlem başlatılıyor."));
  startHashToolButton.disabled = true;
  try {
    const response = await fetch("/hash-tools/jobs", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: mutationHeaders(),
      body: JSON.stringify({
        rule_id: entry.record.ruleId,
        full_line: entry.record.fullLine,
        variant: entry.candidate.variant,
        tool_id: hashToolSelect.value,
        wordlist_upload_id: hashWordlistUpload.upload_id,
        runtime_seconds: Number(hashRuntimeSelect.value),
      }),
    });
    const rawPayload = await responsePayload(response);
    const payload = normalizedHashToolsPayload(rawPayload);
    if (!response.ok || !payload) {
      setHashToolMessage(hashToolErrorMessage(rawPayload?.error), "is-error");
      return;
    }
    hashToolsState = payload;
    renderHashToolAvailability();
    renderHashJob();
  } catch (_error) {
    setHashToolMessage(uiText("Yerel panel yanıt vermedi."), "is-error");
  } finally {
    syncHashToolControls();
    scheduleHashToolsRefresh();
  }
}

async function cancelHashTool() {
  cancelHashToolButton.disabled = true;
  try {
    const response = await fetch("/hash-tools/jobs/cancel", {
      method: "POST",
      credentials: "omit",
      cache: "no-store",
      headers: mutationHeaders(),
      body: "{}",
    });
    const rawPayload = await responsePayload(response);
    const payload = normalizedHashToolsPayload(rawPayload);
    if (!response.ok || !payload) {
      setHashToolMessage(hashToolErrorMessage(rawPayload?.error), "is-error");
      return;
    }
    hashToolsState = payload;
    renderHashJob();
    setHashToolMessage(uiText("Durdurma isteği gönderildi."));
  } catch (_error) {
    setHashToolMessage(uiText("Yerel panel yanıt vermedi."), "is-error");
  } finally {
    syncHashToolControls();
    scheduleHashToolsRefresh();
  }
}

export {
  configureHashTools,
  hashToolErrorMessage,
  refreshHashTools,
  renderHashCandidates,
  setHashScanActive,
};
