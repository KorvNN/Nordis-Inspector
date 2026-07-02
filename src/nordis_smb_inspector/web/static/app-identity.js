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
const EN_CAPABILITY_TITLES = {
  laps_secret_read: "LAPS password data is readable",
  gmsa_secret_read: "gMSA password data is readable",
  ldap_exposed_credential: "A possible credential is readable in an LDAP field",
  directory_replication_read: "Domain password data can be replicated",
  password_reset: "An account password can be reset",
  group_membership_write: "Group membership can be changed",
  object_control: "A directory object can be controlled",
  authentication_material_write: "Authentication material can be changed",
  delegation_write: "Delegation data can be changed",
};

let displayValue;
let statusTone;
let inventoryItems = () => [];
let identityAccessSnapshot = null;

function configureIdentityAccess(dependencies) {
  ({displayValue, statusTone, inventoryItems} = dependencies);
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

function normalizedInventoryValue(value) {
  return String(value ?? "").trim().toLowerCase();
}

function inventoryAccessEvidence() {
  const records = inventoryItems();
  const groups = new Map();
  for (const record of Array.isArray(records) ? records : []) {
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    const target = String(record.target ?? "").trim();
    const share = String(record.share ?? "").trim();
    if (!target || !share) continue;
    const key = `${target.toLocaleLowerCase()}\u001f${share.toLocaleLowerCase()}`;
    if (!groups.has(key)) groups.set(key, {target, share, records: []});
    groups.get(key).records.push(record);
  }

  const evidence = {usable: [], limited: [], denied: []};
  for (const group of groups.values()) {
    const shareRecord = group.records.find(
      (record) => normalizedInventoryValue(record.type) === "share",
    );
    if (!shareRecord) continue;
    const shareStatus = normalizedInventoryValue(shareRecord.status);
    const shareRead = normalizedInventoryValue(shareRecord.readAccess);
    if (shareStatus === "non_file_share") continue;

    const rootListingDenied = group.records.some((record) => (
      normalizedInventoryValue(record.type) === "directory"
      && !String(record.path ?? "").trim()
      && (
        normalizedInventoryValue(record.status).includes("denied")
        || normalizedInventoryValue(record.readAccess) === "denied"
      )
    ));
    const readableChildren = group.records.filter((record) => (
      String(record.path ?? "").trim()
      && normalizedInventoryValue(record.readAccess) === "allowed"
      && !normalizedInventoryValue(record.status).includes("denied")
    ));
    const item = {
      target: group.target,
      share: group.share,
      paths: readableChildren.map((record) => String(record.path)).slice(0, 3),
      readableFiles: readableChildren.filter(
        (record) => normalizedInventoryValue(record.type) === "file",
      ).length,
      readableEntries: readableChildren.length,
    };

    if (shareStatus.includes("denied") || shareRead === "denied") {
      evidence.denied.push(item);
    } else if (shareStatus === "share_connected" && rootListingDenied) {
      evidence.limited.push(item);
    } else if (shareStatus === "share_connected" && shareRead === "allowed") {
      evidence.usable.push(item);
    }
  }

  for (const items of Object.values(evidence)) {
    items.sort((left, right) => (
      `${left.target}\\${left.share}`.localeCompare(`${right.target}\\${right.share}`)
    ));
  }
  return evidence;
}

function smbAccessCard(item, state) {
  const card = document.createElement("article");
  card.className = `identity-smb-access is-${state}`;
  const header = document.createElement("header");
  const title = document.createElement("h4");
  title.textContent = `\\\\${item.target}\\${item.share}`;
  const badge = document.createElement("span");
  badge.textContent = state === "usable"
    ? currentLanguage === "en" ? "Readable" : "Okunabiliyor"
    : currentLanguage === "en" ? "Limited" : "Sınırlı";
  header.append(title, badge);

  const copy = document.createElement("p");
  if (state === "limited") {
    copy.textContent = currentLanguage === "en"
      ? "The share connection succeeded, but listing its root directory was denied."
      : "Share bağlantısı kuruldu ancak kök dizin listesi reddedildi.";
  } else if (item.readableFiles > 0) {
    copy.textContent = currentLanguage === "en"
      ? `${item.readableFiles.toLocaleString(numberLocale())} readable files were observed.`
      : `${item.readableFiles.toLocaleString(numberLocale())} okunabilir dosya görüldü.`;
  } else if (item.readableEntries > 0) {
    copy.textContent = currentLanguage === "en"
      ? `${item.readableEntries.toLocaleString(numberLocale())} readable entries were observed.`
      : `${item.readableEntries.toLocaleString(numberLocale())} okunabilir kayıt görüldü.`;
  } else {
    copy.textContent = currentLanguage === "en"
      ? "Share access and an empty root listing were confirmed."
      : "Share erişimi ve boş kök dizin listesi doğrulandı.";
  }
  card.append(header, copy);

  if (item.paths.length > 0) {
    const paths = document.createElement("div");
    paths.className = "identity-smb-paths";
    for (const pathValue of item.paths) {
      const path = document.createElement("code");
      path.textContent = pathValue;
      paths.append(path);
    }
    card.append(paths);
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
  if (capability.capability_id === "laps_secret_read") {
    return currentLanguage === "en"
      ? "LDAP returned the LAPS password attribute for this identity. The value was not retained."
      : displayValue(capability.summary);
  }
  if (capability.capability_id === "gmsa_secret_read") {
    return currentLanguage === "en"
      ? "LDAP returned the managed password blob for this identity. The value was not retained."
      : displayValue(capability.summary);
  }
  if (capability.capability_id === "ldap_exposed_credential") {
    const rights = Array.isArray(capability.rights) ? capability.rights : [];
    const attribute = displayValue(rights[0]);
    const rule = displayValue(rights[1]);
    return currentLanguage === "en"
      ? `The ${attribute} field matched ${rule}. The value was not retained or validated.`
      : displayValue(capability.summary);
  }
  if (String(capability.evidence_state).toLowerCase() === "inferred") {
    const summaries = {
      tr: {
        secret_read: "Gerekli iki replication hakkı birlikte eşleşiyor; domain parola verisi okunabilir.",
        password_reset: "Eşleşen allow ACE, hedef hesabın parolasını sıfırlama hakkını kapsıyor.",
        group_membership_write: "Eşleşen allow ACE, hedef gruba üye ekleme veya gruptan üye çıkarma hakkını kapsıyor.",
        object_control: "Listelenen sahiplik, DACL veya geniş yazma hakları hedef nesne üzerinde kontrol kurulmasına imkân verebilir.",
        authentication_material_write: "SPN, UAC veya KeyCredentialLink gibi kimlik doğrulamayı etkileyen özellikler yazılabilir.",
        delegation_write: "RBCD delegasyon özelliği yazılabilir ve hedef bilgisayara erişim yolu oluşturabilir.",
      },
      en: {
        secret_read: "Both required replication rights match, so domain password data may be read.",
        password_reset: "The matching allow ACE includes the right to reset the target account password.",
        group_membership_write: "The matching allow ACE includes the right to add or remove members on the target group.",
        object_control: "The listed ownership, DACL, or broad write rights may establish control over the target object.",
        authentication_material_write: "Authentication-related attributes such as SPN, UAC, or KeyCredentialLink can be written.",
        delegation_write: "The RBCD delegation attribute can be written and may create an access path to the target computer.",
      },
    };
    const summary = summaries[currentLanguage]?.[capability.kind];
    if (summary) return summary;
  }
  if (currentLanguage !== "en") return displayValue(capability.summary);
  const via = displayValue(capability.via_principal);
  const subject = displayValue(capability.subject);
  return `A directly matching allow ACE for ${via} indicates this access on ${subject}. Nordis made no directory change.`;
}

function capabilityNextStep(capability) {
  if (Number(capability.aggregate_count) > 1) return null;
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

function aggregateCapabilityTitle(capability) {
  const count = Number(capability.aggregate_count);
  const amount = count.toLocaleString(numberLocale());
  const subjectType = String(capability.subject_type ?? "").toLowerCase();
  if (currentLanguage === "en") {
    const titles = {
      secret_read: `${amount} targets expose secret data`,
      password_reset: `${amount} account passwords can be reset`,
      group_membership_write: `Membership of ${amount} groups can be changed`,
      authentication_material_write: `Authentication data on ${amount} accounts can be changed`,
      delegation_write: `Delegation data on ${amount} targets can be changed`,
    };
    if (capability.kind === "object_control") {
      const nouns = {user: "user objects", group: "group objects", computer: "computer objects"};
      return `${amount} ${nouns[subjectType] ?? "directory objects"} can be controlled`;
    }
    return titles[capability.kind] ?? `${amount} usable AD rights`;
  }
  const titles = {
    secret_read: `${amount} hedefte gizli veri okunabiliyor`,
    password_reset: `${amount} hesabın parolası sıfırlanabilir`,
    group_membership_write: `${amount} grubun üyeliği değiştirilebilir`,
    authentication_material_write: `${amount} hesapta kimlik doğrulama verisi değiştirilebilir`,
    delegation_write: `${amount} hedefte delegasyon verisi değiştirilebilir`,
  };
  if (capability.kind === "object_control") {
    const nouns = {user: "kullanıcı nesnesi", group: "grup nesnesi", computer: "bilgisayar nesnesi"};
    return `${amount} ${nouns[subjectType] ?? "directory nesnesi"} kontrol edilebilir`;
  }
  return titles[capability.kind] ?? `${amount} kullanılabilir AD yetkisi`;
}

function aggregateTargetLabel(capability) {
  const count = Number(capability.aggregate_count);
  const amount = count.toLocaleString(numberLocale());
  const subjectType = String(capability.subject_type ?? "").toLowerCase();
  if (currentLanguage === "en") return `Show ${amount} targets`;
  const labels = {
    user: `${amount} kullanıcıyı göster`,
    group: `${amount} grubu göster`,
    computer: `${amount} bilgisayarı göster`,
    gmsa: `${amount} gMSA hesabını göster`,
  };
  return labels[subjectType] ?? `${amount} hedefi göster`;
}

function groupCapabilities(capabilities) {
  const groups = new Map();
  for (const capability of capabilities) {
    const rights = Array.isArray(capability.rights)
      ? capability.rights.map(String).sort((left, right) => left.localeCompare(right))
      : [];
    const key = JSON.stringify([
      capability.capability_id,
      capability.kind,
      capability.evidence_state,
      capability.subject_type,
      capability.via_principal,
      rights,
    ]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(capability);
  }
  return [...groups.values()].map((items) => {
    if (items.length === 1) return items[0];
    const subjects = [...new Set(items.map((item) => String(item.subject ?? "")).filter(Boolean))]
      .sort((left, right) => left.localeCompare(right));
    return {...items[0], aggregate_count: items.length, subjects};
  });
}

function capabilityCard(capability) {
  const card = document.createElement("article");
  card.className = "identity-capability";
  const header = document.createElement("header");
  header.className = "identity-capability-header";
  const title = document.createElement("h4");
  title.textContent = Number(capability.aggregate_count) > 1
    ? aggregateCapabilityTitle(capability)
    : capabilityTitle(capability);
  const evidenceKey = String(capability.evidence_state ?? "inferred").toLowerCase();
  const evidence = document.createElement("span");
  evidence.className = `identity-evidence is-${evidenceKey}`;
  evidence.textContent = identityLabel(
    IDENTITY_EVIDENCE_LABELS,
    evidenceKey,
    displayValue(evidenceKey),
  );
  header.append(title, evidence);

  const summary = document.createElement("p");
  summary.className = "identity-capability-summary";
  summary.textContent = capabilitySummary(capability);
  card.append(header);
  if (Number(capability.aggregate_count) <= 1) {
    const subject = document.createElement("p");
    subject.className = "identity-subject";
    subject.textContent = displayValue(capability.subject);
    card.append(subject);
  }
  card.append(summary);

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

  if (Number(capability.aggregate_count) > 1) {
    const targets = document.createElement("details");
    targets.className = "identity-capability-targets";
    const targetsSummary = document.createElement("summary");
    targetsSummary.textContent = aggregateTargetLabel(capability);
    const targetList = document.createElement("div");
    targetList.className = "identity-capability-target-list";
    for (const subjectValue of capability.subjects ?? []) {
      const item = document.createElement("code");
      item.textContent = subjectValue;
      targetList.append(item);
    }
    targets.append(targetsSummary, targetList);
    card.append(targets);
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
  const capabilities = (Array.isArray(report?.capabilities) ? report.capabilities : [])
    .filter((item) => item && typeof item === "object" && !Array.isArray(item));
  const capabilityGroups = groupCapabilities(capabilities);
  const smbEvidence = inventoryAccessEvidence();
  const usefulEvidenceCount = capabilityGroups.length + smbEvidence.usable.length;
  identityTabCount.textContent = usefulEvidenceCount.toLocaleString(numberLocale());

  const reportIsPartial = status === "completed" && report?.partial === true;
  identityAccessStatus.textContent = reportIsPartial
    ? currentLanguage === "en" ? "AD result incomplete" : "AD sonucu eksik"
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
  const smbSection = resultSection(
    currentLanguage === "en" ? "Usable SMB access" : "Kullanılabilir SMB erişimleri",
    currentLanguage === "en"
      ? "Only observed access for the supplied identity is shown."
      : "Yalnızca girilen kimlikle gözlenen erişimler gösterilir.",
  );
  const smbList = document.createElement("div");
  smbList.className = "identity-smb-list";
  for (const item of smbEvidence.usable) smbList.append(smbAccessCard(item, "usable"));
  if (smbEvidence.usable.length === 0) {
    const empty = document.createElement("div");
    empty.className = "identity-no-capability";
    const title = document.createElement("strong");
    title.textContent = currentLanguage === "en"
      ? "No readable SMB share was confirmed"
      : "Okunabilir SMB share doğrulanmadı";
    empty.append(title);
    smbList.append(empty);
  }
  for (const item of smbEvidence.limited) smbList.append(smbAccessCard(item, "limited"));
  if (smbEvidence.denied.length > 0) {
    const denied = document.createElement("details");
    denied.className = "identity-denied-access";
    const summary = document.createElement("summary");
    summary.textContent = currentLanguage === "en"
      ? `${smbEvidence.denied.length.toLocaleString(numberLocale())} denied shares`
      : `${smbEvidence.denied.length.toLocaleString(numberLocale())} reddedilen share`;
    const list = document.createElement("div");
    list.className = "identity-denied-list";
    for (const item of smbEvidence.denied) {
      const path = document.createElement("code");
      path.textContent = `\\\\${item.target}\\${item.share}`;
      list.append(path);
    }
    denied.append(summary, list);
    smbList.append(denied);
  }
  smbSection.append(smbList);

  const capabilitySection = resultSection(
    currentLanguage === "en" ? "Usable AD access" : "Kullanılabilir AD erişimleri",
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
      ? "No directly usable AD right was confirmed"
      : "Doğrudan kullanılabilir AD yetkisi doğrulanmadı";
    const copy = document.createElement("p");
    copy.textContent = currentLanguage === "en"
      ? "No readable managed password or directly matching usable ACL right was found."
      : "Okunabilir yönetilen parola veya doğrudan eşleşen kullanılabilir ACL yetkisi bulunmadı.";
    empty.append(title, copy);
    capabilityList.append(empty);
  } else {
    for (const capability of capabilityGroups) {
      capabilityList.append(capabilityCard(capability));
    }
  }
  capabilitySection.append(capabilityList);

  layout.append(smbSection, capabilitySection);
  identityAccessContent.append(layout);
}

export {
  configureIdentityAccess,
  currentIdentityAccess,
  renderIdentityAccess,
};
