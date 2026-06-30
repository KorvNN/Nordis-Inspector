"use strict";

import {currentLanguage, numberLocale} from "./app-i18n.js";

const identityAccessStatus = document.querySelector("#identity-access-status");
const identityAccessContent = document.querySelector("#identity-access-content");
const identityTabCount = document.querySelector("#identity-tab-count");

const IDENTITY_STATUS_LABELS = {
  tr: {
    pending: "Bekliyor",
    running: "İnceleniyor",
    completed: "Tamamlandı",
    failed: "Tamamlanamadı",
    not_checked: "İncelenmedi",
  },
  en: {
    pending: "Pending",
    running: "Inspecting",
    completed: "Completed",
    failed: "Could not complete",
    not_checked: "Not inspected",
  },
};
const IDENTITY_EVIDENCE_LABELS = {
  tr: {verified: "Doğrulandı", inferred: "Çıkarım"},
  en: {verified: "Verified", inferred: "Inferred"},
};
const IDENTITY_COVERAGE_LABELS = {
  tr: {completed: "Tamamlandı", partial: "Kısmi", not_checked: "İncelenmedi"},
  en: {completed: "Completed", partial: "Partial", not_checked: "Not inspected"},
};
const EN_CAPABILITY_TITLES = {
  laps_secret_read: "LAPS password data is readable",
  gmsa_secret_read: "gMSA password data is readable",
  directory_replication_read: "Domain password data can be replicated",
  password_reset: "An account password can be reset",
  group_membership_write: "Group membership can be changed",
  object_control: "A directory object can be controlled",
  authentication_material_write: "Authentication material can be changed",
  delegation_write: "Delegation data can be changed",
};

let displayValue;
let statusTone;
let identityAccessSnapshot = null;

function configureIdentityAccess(dependencies) {
  ({displayValue, statusTone} = dependencies);
}

function currentIdentityAccess() {
  return identityAccessSnapshot;
}

function identityLabel(labels, key, fallback = key) {
  return labels[currentLanguage]?.[key] ?? fallback;
}

function identityStateCopy(status) {
  const copies = {
    tr: {
      pending: [
        "Kimlik erişimi bekliyor.",
        "SMB taraması tamamlandıktan sonra uygun bir domain controller görülürse inceleme başlayacak.",
      ],
      running: [
        "Kimlik erişimi inceleniyor.",
        "Girilen kullanıcıyla doğrudan kullanılabilecek erişimler kontrol ediliyor.",
      ],
      failed: [
        "Kimlik erişimi tamamlanamadı.",
        "SMB sonuçları geçerlidir; yalnızca bu kimlik incelemesi tamamlanamadı.",
      ],
      not_checked: [
        "Kimlik erişimi incelenmedi.",
        "Bu taramada kimlik incelemesini başlatacak doğrulanmış bir domain controller adayı oluşmadı.",
      ],
    },
    en: {
      pending: [
        "Identity access is pending.",
        "Inspection will start after the SMB scan if an eligible domain controller is observed.",
      ],
      running: [
        "Inspecting identity access.",
        "Checking directly usable access for the supplied user.",
      ],
      failed: [
        "Identity access could not be completed.",
        "The SMB results remain valid; only this identity inspection could not be completed.",
      ],
      not_checked: [
        "Identity access was not inspected.",
        "This scan did not produce a verified domain controller candidate for identity inspection.",
      ],
    },
  };
  return copies[currentLanguage]?.[status] ?? copies.tr.not_checked;
}

function identityEmptyState(status, payload) {
  const state = document.createElement("div");
  state.className = `identity-empty-state ${status === "failed" ? "is-error" : ""} ${
    ["pending", "running"].includes(status) ? "is-running" : ""
  }`.trim();
  const [defaultTitle, defaultMessage] = identityStateCopy(status);
  const title = document.createElement("strong");
  title.textContent = defaultTitle;
  const message = document.createElement("p");
  message.textContent = payload?.error?.message ?? payload?.message ?? defaultMessage;
  state.append(title, message);
  const codeValue = payload?.error?.code;
  if (typeof codeValue === "string" && codeValue.trim() !== "") {
    const code = document.createElement("code");
    code.className = "identity-state-code";
    code.textContent = codeValue;
    state.append(code);
  }
  return state;
}

function identityFact(label, value) {
  const fact = document.createElement("div");
  fact.className = "identity-fact";
  const term = document.createElement("span");
  term.textContent = label;
  const description = document.createElement("strong");
  description.textContent = displayValue(value);
  fact.append(term, description);
  return fact;
}

function identitySummary(report) {
  const identity = report.identity ?? {};
  const groups = Array.isArray(identity.groups) ? identity.groups : [];
  const card = document.createElement("section");
  card.className = "identity-summary-card";
  const top = document.createElement("div");
  top.className = "identity-summary-top";
  const principalBlock = document.createElement("div");
  const eyebrow = document.createElement("span");
  eyebrow.className = "identity-eyebrow";
  eyebrow.textContent = currentLanguage === "en" ? "SUPPLIED IDENTITY" : "GİRİLEN KİMLİK";
  const principal = document.createElement("h3");
  principal.className = "identity-principal";
  principal.textContent = displayValue(identity.principal);
  principalBlock.append(eyebrow, principal);
  top.append(principalBlock);

  const facts = document.createElement("div");
  facts.className = "identity-facts";
  facts.append(
    identityFact("Domain", identity.domain),
    identityFact("Domain controller", report.controller),
    identityFact(
      currentLanguage === "en" ? "Authentication" : "Kimlik doğrulama",
      report.authentication_method,
    ),
    identityFact(
      currentLanguage === "en" ? "Effective groups" : "Etkin grup",
      groups.length.toLocaleString(numberLocale()),
    ),
  );
  card.append(top, facts);

  if (groups.length > 0) {
    const details = document.createElement("details");
    details.className = "identity-groups";
    const summary = document.createElement("summary");
    summary.textContent = currentLanguage === "en"
      ? `Show ${groups.length.toLocaleString(numberLocale())} effective groups`
      : `${groups.length.toLocaleString(numberLocale())} etkin grubu göster`;
    const list = document.createElement("ul");
    list.className = "identity-group-list";
    for (const group of groups) {
      const item = document.createElement("li");
      item.textContent = displayValue(group?.name);
      if (typeof group?.sid === "string") item.title = group.sid;
      list.append(item);
    }
    details.append(summary, list);
    card.append(details);
  }
  return card;
}

function capabilityTitle(capability) {
  if (currentLanguage !== "en") return displayValue(capability.title);
  return EN_CAPABILITY_TITLES[capability.capability_id]
    ?? EN_CAPABILITY_TITLES[capability.kind]
    ?? displayValue(capability.title);
}

function capabilitySummary(capability) {
  if (currentLanguage !== "en") return displayValue(capability.summary);
  if (capability.capability_id === "laps_secret_read") {
    return "LDAP returned the LAPS password attribute for this identity. The value was not retained.";
  }
  if (capability.capability_id === "gmsa_secret_read") {
    return "LDAP returned the managed password blob for this identity. The value was not retained.";
  }
  const via = displayValue(capability.via_principal);
  const subject = displayValue(capability.subject);
  return `A directly matching allow ACE for ${via} indicates this access on ${subject}. Nordis made no directory change.`;
}

function capabilityNextStep(capability) {
  if (currentLanguage !== "en") return capability.next_step;
  const subject = displayValue(capability.subject);
  const labels = {
    secret_read: `Validate the authorized access scope for ${subject} independently.`,
    password_reset: `Review the access provided by ${subject}; Nordis did not change the password.`,
    group_membership_write: `Review the access provided by ${subject}; Nordis did not change membership.`,
    object_control: `Validate the ACE scope on ${subject}; Nordis did not change the object.`,
    authentication_material_write: `Validate the account impact of the writable property on ${subject}.`,
    delegation_write: `Validate the delegation target and possible access scope for ${subject}.`,
  };
  return labels[capability.kind] ?? capability.next_step;
}

function capabilityCard(capability) {
  const card = document.createElement("article");
  card.className = "identity-capability";
  const header = document.createElement("header");
  header.className = "identity-capability-header";
  const title = document.createElement("h4");
  title.textContent = capabilityTitle(capability);
  const evidenceKey = String(capability.evidence_state ?? "inferred").toLowerCase();
  const evidence = document.createElement("span");
  evidence.className = `identity-evidence is-${evidenceKey}`;
  evidence.textContent = identityLabel(
    IDENTITY_EVIDENCE_LABELS,
    evidenceKey,
    displayValue(evidenceKey),
  );
  header.append(title, evidence);

  const subject = document.createElement("p");
  subject.className = "identity-subject";
  subject.textContent = displayValue(capability.subject);
  const summary = document.createElement("p");
  summary.className = "identity-capability-summary";
  summary.textContent = capabilitySummary(capability);
  card.append(header, subject, summary);

  const via = capability.via_principal;
  const rights = Array.isArray(capability.rights) ? capability.rights : [];
  if ((typeof via === "string" && via !== "") || rights.length > 0) {
    const metadata = document.createElement("div");
    metadata.className = "identity-capability-meta";
    if (typeof via === "string" && via !== "") {
      const row = document.createElement("div");
      row.className = "identity-meta-row";
      row.append(document.createTextNode(`${currentLanguage === "en" ? "Via" : "Üzerinden"}: `));
      const value = document.createElement("strong");
      value.textContent = via;
      row.append(value);
      metadata.append(row);
    }
    if (rights.length > 0) {
      const rightList = document.createElement("div");
      rightList.className = "identity-rights";
      for (const right of rights) {
        const item = document.createElement("span");
        item.className = "identity-right";
        item.textContent = displayValue(right);
        rightList.append(item);
      }
      metadata.append(rightList);
    }
    card.append(metadata);
  }

  const nextStepValue = capabilityNextStep(capability);
  if (typeof nextStepValue === "string" && nextStepValue.trim() !== "") {
    const nextStep = document.createElement("p");
    nextStep.className = "identity-next-step";
    const label = document.createElement("strong");
    label.textContent = currentLanguage === "en" ? "Validation step: " : "Doğrulama adımı: ";
    nextStep.append(label, document.createTextNode(nextStepValue));
    card.append(nextStep);
  }
  return card;
}

function coverageItem(coverage) {
  const item = document.createElement("article");
  item.className = "identity-coverage-item";
  const header = document.createElement("div");
  header.className = "identity-coverage-header";
  const label = document.createElement("strong");
  label.textContent = displayValue(coverage.label);
  const stateKey = String(coverage.state ?? "not_checked").toLowerCase();
  const state = document.createElement("span");
  state.className = `identity-coverage-state is-${stateKey.replaceAll("_", "-")}`;
  state.textContent = identityLabel(
    IDENTITY_COVERAGE_LABELS,
    stateKey,
    displayValue(stateKey),
  );
  header.append(label, state);
  item.append(header);

  const recordsSeen = Number.isFinite(coverage.records_seen) ? coverage.records_seen : 0;
  const records = document.createElement("p");
  records.className = "identity-coverage-meta";
  records.textContent = currentLanguage === "en"
    ? `${recordsSeen.toLocaleString(numberLocale())} records inspected.`
    : `${recordsSeen.toLocaleString(numberLocale())} kayıt incelendi.`;
  item.append(records);
  if (typeof coverage.message === "string" && coverage.message.trim() !== "") {
    const message = document.createElement("p");
    message.className = "identity-coverage-meta";
    message.textContent = coverage.message;
    item.append(message);
  }
  return item;
}

function resultSection(titleText, descriptionText) {
  const section = document.createElement("section");
  section.className = "identity-result-section";
  const heading = document.createElement("header");
  heading.className = "identity-section-heading";
  const title = document.createElement("h3");
  title.textContent = titleText;
  const description = document.createElement("p");
  description.textContent = descriptionText;
  heading.append(title, description);
  section.append(heading);
  return section;
}

function renderIdentityAccess(payload) {
  const validPayload = payload && typeof payload === "object" && !Array.isArray(payload)
    ? payload
    : null;
  identityAccessSnapshot = validPayload;
  const status = String(validPayload?.status ?? "not_checked").toLowerCase();
  const report = validPayload?.report && typeof validPayload.report === "object"
    && !Array.isArray(validPayload.report)
    ? validPayload.report
    : null;
  const capabilities = Array.isArray(report?.capabilities) ? report.capabilities : [];
  identityTabCount.textContent = capabilities.length.toLocaleString(numberLocale());

  const reportIsPartial = status === "completed" && report?.partial === true;
  identityAccessStatus.textContent = reportIsPartial
    ? currentLanguage === "en" ? "Partial coverage" : "Kısmi kapsam"
    : identityLabel(IDENTITY_STATUS_LABELS, status, displayValue(status));
  identityAccessStatus.className = `status-value ${
    reportIsPartial ? "is-working" : statusTone(status)
  }`.trim();
  identityAccessContent.replaceChildren();

  if (status !== "completed") {
    identityAccessContent.append(identityEmptyState(status, validPayload));
    return;
  }
  if (report === null) {
    identityAccessContent.append(identityEmptyState("failed", {
      error: {
        code: "IDENTITY_RESULT_UNAVAILABLE",
        message: currentLanguage === "en"
          ? "The completed identity result could not be read."
          : "Tamamlanan kimlik sonucu okunamadı.",
      },
    }));
    return;
  }

  identityAccessContent.append(identitySummary(report));
  const layout = document.createElement("div");
  layout.className = "identity-results-layout";
  const capabilitySection = resultSection(
    currentLanguage === "en" ? "Directly usable access" : "Doğrudan kullanılabilir erişimler",
    currentLanguage === "en"
      ? "Verified items come from LDAP responses; inferred items come from a direct ACL match."
      : "Doğrulananlar LDAP yanıtından, çıkarımlar doğrudan ACL eşleşmesinden gelir.",
  );
  const capabilityList = document.createElement("div");
  capabilityList.className = "identity-capability-list";
  if (capabilities.length === 0) {
    const empty = document.createElement("div");
    empty.className = "identity-no-capability";
    const title = document.createElement("strong");
    title.textContent = currentLanguage === "en"
      ? "No direct access evidence was found"
      : "Doğrudan erişim kanıtı bulunmadı";
    const copy = document.createElement("p");
    copy.textContent = currentLanguage === "en"
      ? "This does not mean the account is ineffective or the environment is clean. Review coverage before interpreting the result."
      : "Bu, hesabın etkisiz veya ortamın temiz olduğu anlamına gelmez. Sonucu yorumlamadan önce kontrol kapsamını inceleyin.";
    empty.append(title, copy);
    capabilityList.append(empty);
  } else {
    for (const capability of capabilities) {
      if (!capability || typeof capability !== "object" || Array.isArray(capability)) continue;
      capabilityList.append(capabilityCard(capability));
    }
  }
  capabilitySection.append(capabilityList);

  const coverageSection = resultSection(
    currentLanguage === "en" ? "Check coverage" : "Kontrol kapsamı",
    currentLanguage === "en"
      ? "Incomplete checks are not treated as clean."
      : "Tamamlanmayan kontroller temiz kabul edilmez.",
  );
  const coverageList = document.createElement("div");
  coverageList.className = "identity-coverage-list";
  const coverageItems = Array.isArray(report.coverage) ? report.coverage : [];
  for (const coverage of coverageItems) {
    if (!coverage || typeof coverage !== "object" || Array.isArray(coverage)) continue;
    coverageList.append(coverageItem(coverage));
  }
  if (coverageList.childElementCount === 0) {
    const empty = document.createElement("p");
    empty.className = "identity-coverage-meta";
    empty.textContent = currentLanguage === "en"
      ? "Coverage information is unavailable."
      : "Kapsam bilgisi alınamadı.";
    coverageList.append(empty);
  }
  coverageSection.append(coverageList);
  layout.append(capabilitySection, coverageSection);
  identityAccessContent.append(layout);
}

export {
  configureIdentityAccess,
  currentIdentityAccess,
  renderIdentityAccess,
};
