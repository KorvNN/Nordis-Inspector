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
  tr: {
    verified: "Doğrulandı",
    acl_indicated: "Yetki işaret ediyor",
    inferred: "Yetki işaret ediyor",
    unresolved: "Belirsiz",
  },
  en: {
    verified: "Verified",
    acl_indicated: "ACL indicates access",
    inferred: "ACL indicates access",
    unresolved: "Unresolved",
  },
};
const EN_CAPABILITY_TITLES = {
  laps_secret_read: "LAPS password data is readable",
  gmsa_secret_read: "gMSA password data is readable",
  directory_replication_read: "Domain password data can be replicated",
  password_reset: "An account password can be reset",
  group_membership_write: "Group membership can be changed",
  spn_write: "The SPN value can be changed",
  account_control_write: "Account-control settings can be changed",
  key_credential_write: "The Key Credential value can be changed",
  rbcd_write: "RBCD delegation can be changed",
  dacl_write: "The object DACL can be changed",
  owner_write: "The object owner can be changed",
  object_full_control: "The identity has full control of the object",
  object_property_write: "Object properties can be changed",
  object_delete: "The directory object can be deleted",
  child_create: "A child object can be created",
  child_delete: "A child object can be deleted",
  all_extended_rights: "All extended rights are available",
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
        "Hedef incelemesi tamamlandıktan sonra uygun bir domain controller bulunursa AD incelemesi başlayacak.",
      ],
      running: [
        "Kimlik erişimi inceleniyor.",
        "Girilen kullanıcıyla doğrudan kullanılabilecek erişimler kontrol ediliyor.",
      ],
      failed: [
        "Kimlik erişimi tamamlanamadı.",
        "Hedef tarama sonuçları geçerlidir; yalnızca AD kimlik incelemesi tamamlanamadı.",
      ],
      not_checked: [
        "Kimlik erişimi incelenmedi.",
        "Bu taramada kimlik incelemesini başlatacak doğrulanmış bir domain controller adayı oluşmadı.",
      ],
    },
    en: {
      pending: [
        "Identity access is pending.",
        "AD inspection will start after target inspection if an eligible domain controller is found.",
      ],
      running: [
        "Inspecting identity access.",
        "Checking directly usable access for the supplied user.",
      ],
      failed: [
        "Identity access could not be completed.",
        "The target scan results remain valid; only the AD identity inspection could not be completed.",
      ],
      not_checked: [
        "Identity access was not inspected.",
        "This scan did not produce a verified domain controller candidate for identity inspection.",
      ],
    },
  };
  return copies[currentLanguage]?.[status] ?? copies.tr.not_checked;
}

function identityLoadingSkeleton() {
  const skeleton = document.createElement("div");
  skeleton.className = "identity-loading-skeleton";
  skeleton.setAttribute("aria-hidden", "true");

  for (let cardIndex = 0; cardIndex < 3; cardIndex += 1) {
    const card = document.createElement("div");
    card.className = "identity-skeleton-card";
    const heading = document.createElement("span");
    heading.className = "identity-skeleton-line is-heading";
    card.append(heading);
    for (let lineIndex = 0; lineIndex < 2; lineIndex += 1) {
      const line = document.createElement("span");
      line.className = "identity-skeleton-line";
      card.append(line);
    }
    skeleton.append(card);
  }
  return skeleton;
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
  const copy = document.createElement("div");
  copy.className = "identity-state-copy";
  copy.append(title, message);
  state.append(copy);
  if (status === "running") state.append(identityLoadingSkeleton());
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
  if (capability.capability_id === "all_extended_rights") {
    const evidenceState = String(capability.evidence_state ?? "acl_indicated").toLowerCase();
    if (currentLanguage === "en") {
      return evidenceState === "unresolved"
        ? "Extended-right access could not be resolved"
        : "An ACL indicates all extended rights";
    }
    return evidenceState === "unresolved"
      ? "Genişletilmiş haklar kesinleştirilemedi"
      : "Tüm genişletilmiş haklara işaret eden ACL bulundu";
  }
  if (currentLanguage !== "en") return displayValue(capability.title);
  return EN_CAPABILITY_TITLES[capability.capability_id]
    ?? EN_CAPABILITY_TITLES[capability.kind]
    ?? displayValue(capability.title);
}

function capabilityAction(capability) {
  const actions = {
    tr: {
      laps_secret_read: "LAPS parolasını okuma",
      gmsa_secret_read: "gMSA parolasını okuma",
      directory_replication_read: "domain parola verisini çoğaltma",
      password_reset: "hesap parolasını sıfırlama",
      group_membership_write: "grup üyeliğini değiştirme",
      spn_write: "SPN değerini değiştirme",
      account_control_write: "hesap denetim seçeneklerini değiştirme",
      key_credential_write: "Key Credential değerini değiştirme",
      rbcd_write: "RBCD delegasyonunu değiştirme",
      dacl_write: "nesne DACL'ini değiştirme",
      owner_write: "nesne sahibini değiştirme",
      object_full_control: "nesne üzerinde tam kontrol kullanma",
      object_property_write: "nesne özelliklerini değiştirme",
      object_delete: "nesneyi silme",
      child_create: "alt nesne oluşturma",
      child_delete: "alt nesne silme",
      all_extended_rights: "tüm genişletilmiş hakları kullanma",
    },
    en: {
      laps_secret_read: "read a LAPS password",
      gmsa_secret_read: "read a gMSA password",
      directory_replication_read: "replicate domain password data",
      password_reset: "reset an account password",
      group_membership_write: "change group membership",
      spn_write: "change an SPN value",
      account_control_write: "change account-control settings",
      key_credential_write: "change a Key Credential value",
      rbcd_write: "change RBCD delegation",
      dacl_write: "change an object DACL",
      owner_write: "change an object owner",
      object_full_control: "fully control an object",
      object_property_write: "change object properties",
      object_delete: "delete an object",
      child_create: "create a child object",
      child_delete: "delete a child object",
      all_extended_rights: "use all extended rights",
    },
  };
  return actions[currentLanguage]?.[capability.capability_id]
    ?? (currentLanguage === "en" ? "perform this AD action" : "bu AD eylemini kullanma");
}

function identityAccountName(identityPrincipal) {
  const principal = String(identityPrincipal ?? "").trim();
  if (principal === "") return currentLanguage === "en" ? "The supplied identity" : "Girilen kimlik";
  const domainSeparator = principal.lastIndexOf("\\");
  const account = domainSeparator >= 0 ? principal.slice(domainSeparator + 1) : principal;
  return account.includes("@") ? account.slice(0, account.indexOf("@")) : account;
}

function capabilityScope(capability) {
  const count = Number(capability.aggregate_count);
  if (count > 1) {
    const amount = count.toLocaleString(numberLocale());
    return currentLanguage === "en" ? `across ${amount} targets` : `${amount} hedefte`;
  }
  const subject = displayValue(capability.subject);
  return currentLanguage === "en" ? `on ${subject}` : `${subject} üzerinde`;
}

function extendedRightsImpact(capability) {
  if (capability.capability_id !== "all_extended_rights") return "";
  const subjectType = String(capability.subject_type ?? "").toLowerCase();
  if (currentLanguage === "en") {
    if (["user", "computer"].includes(subjectType)) {
      return " This includes operations such as resetting the target account password.";
    }
    if (subjectType === "domaindns") {
      return " This includes operations such as replicating domain password data.";
    }
    return " The concrete operations depend on the target object type.";
  }
  if (["user", "computer"].includes(subjectType)) {
    return " Buna hedef hesabın parolasını sıfırlama gibi işlemler dahildir.";
  }
  if (subjectType === "domaindns") {
    return " Buna domain parola verisini çoğaltma gibi işlemler dahildir.";
  }
  return " Yapılabilecek somut işlemler hedef nesnenin türüne bağlıdır.";
}

function capabilitySummary(capability, identityPrincipal) {
  const actor = identityAccountName(identityPrincipal);
  const principal = String(identityPrincipal ?? "").trim().toLowerCase();
  const via = String(capability.via_principal ?? "").trim();
  const viaIsActor = via !== "" && [principal, actor.toLowerCase()].includes(via.toLowerCase());
  const route = via !== "" && !viaIsActor
    ? (currentLanguage === "en" ? ` through ${via}` : `, ${via} üzerinden`)
    : "";
  const scope = capabilityScope(capability);
  const action = capabilityAction(capability);
  const evidenceState = String(capability.evidence_state ?? "acl_indicated").toLowerCase();
  const impact = extendedRightsImpact(capability);

  if (currentLanguage === "en") {
    if (evidenceState === "verified") {
      const retained = ["laps_secret_read", "gmsa_secret_read"].includes(
        capability.capability_id,
      )
        ? " The secret value was not retained."
        : " Nordis Inspector made no persistent change.";
      return `${actor}${route} was verified to have permission to ${action} ${scope}.${impact}${retained}`;
    }
    if (evidenceState === "unresolved") {
      return `An ACL indicates that ${actor}${route} may have permission to ${action} ${scope}, but deny or unsupported ACEs prevent a conclusive result.${impact}`;
    }
    return `${actor}${route} appears to have permission to ${action} ${scope}.${impact} This result is based only on the ACL; Nordis Inspector did not perform the action.`;
  }

  const account = actor === "Girilen kimlik" ? actor : `${actor} hesabı`;
  if (evidenceState === "verified") {
    const retained = ["laps_secret_read", "gmsa_secret_read"].includes(
      capability.capability_id,
    )
      ? " Gizli değer saklanmadı."
      : " Nordis Inspector kalıcı değişiklik yapmadı.";
    return `${account}${route} ${scope} ${action} yetkisine sahip. Bu erişim canlı olarak doğrulandı.${impact}${retained}`;
  }
  if (evidenceState === "unresolved") {
    return `${account}${route} ${scope} ${action} yetkisine sahip olabilir. Deny veya desteklenmeyen ACE'ler nedeniyle sonuç kesin değil.${impact}`;
  }
  return `${account}${route} ${scope} ${action} yetkisine sahip görünüyor.${impact} Bu sonuç yalnızca ACL kaydına dayanıyor; Nordis Inspector aktif işlem yapmadı.`;
}

function capabilityNextStep(capability) {
  if (Number(capability.aggregate_count) > 1) return null;
  if (currentLanguage !== "en") return capability.next_step;
  const subject = displayValue(capability.subject);
  const labels = {
    directory_replication_read: `Validate both required replication rights on ${subject}.`,
    password_reset: `Review the access provided by ${subject}; Nordis Inspector did not change the password.`,
    group_membership_write: `Review the access provided by ${subject}; Nordis Inspector did not change membership.`,
    spn_write: `Assess the targeted Kerberoast impact for ${subject}; Nordis Inspector did not change the SPN.`,
    account_control_write: `Review which account flags can be changed on ${subject}.`,
    key_credential_write: `Assess the Shadow Credentials impact for ${subject}.`,
    rbcd_write: `Validate the RBCD target and resulting access scope for ${subject}.`,
    dacl_write: `Review the rights that could be granted on ${subject}; Nordis Inspector did not change its DACL.`,
    owner_write: `Validate how ownership would affect DACL control on ${subject}.`,
  };
  return labels[capability.capability_id]
    ?? `Validate the matching ACL scope on ${subject}; Nordis Inspector made no directory change.`;
}

function appendBrandedIdentityText(element, value) {
  const text = displayValue(value);
  const brandPattern = /\bNordis(?: Inspector)?\b/gu;
  let offset = 0;
  for (const match of text.matchAll(brandPattern)) {
    if (match.index > offset) {
      element.append(document.createTextNode(text.slice(offset, match.index)));
    }
    const brand = document.createElement("strong");
    brand.textContent = "Nordis Inspector";
    element.append(brand);
    offset = match.index + match[0].length;
  }
  if (offset < text.length) {
    element.append(document.createTextNode(text.slice(offset)));
  }
}

function appendHighlightedCapabilitySummary(
  element,
  value,
  capability,
  identityPrincipal,
) {
  const text = displayValue(value);
  const actor = identityAccountName(identityPrincipal);
  const via = String(capability.via_principal ?? "").trim();
  const tokens = [
    [actor, "is-actor"],
    [via, "is-via"],
    [capabilityScope(capability), "is-scope"],
    [capabilityAction(capability), "is-action"],
    ["Nordis Inspector", "is-brand"],
  ].filter(([token], index, values) => (
    token !== ""
    && values.findIndex(([candidate]) => candidate === token) === index
  ));
  let offset = 0;
  while (offset < text.length) {
    let selected = null;
    for (const [token, className] of tokens) {
      const index = text.indexOf(token, offset);
      if (index < 0) continue;
      if (selected === null || index < selected.index
          || (index === selected.index && token.length > selected.token.length)) {
        selected = {token, className, index};
      }
    }
    if (selected === null) {
      element.append(document.createTextNode(text.slice(offset)));
      return;
    }
    if (selected.index > offset) {
      element.append(document.createTextNode(text.slice(offset, selected.index)));
    }
    const emphasis = document.createElement("strong");
    emphasis.className = `identity-summary-token ${selected.className}`;
    emphasis.textContent = selected.token;
    element.append(emphasis);
    offset = selected.index + selected.token.length;
  }
}

function aggregateCapabilityTitle(capability) {
  const count = Number(capability.aggregate_count);
  const amount = count.toLocaleString(numberLocale());
  const evidenceState = String(capability.evidence_state ?? "acl_indicated").toLowerCase();
  const subjects = aggregateSubjectCount(capability);
  if (capability.capability_id === "all_extended_rights") {
    if (currentLanguage === "en") {
      return evidenceState === "unresolved"
        ? `Extended-right access on ${subjects} could not be resolved`
        : `An ACL indicates all extended rights on ${subjects}`;
    }
    return evidenceState === "unresolved"
      ? `${subjects} için genişletilmiş haklar kesinleştirilemedi`
      : `${subjects} için tüm genişletilmiş haklara işaret eden ACL bulundu`;
  }
  if (currentLanguage === "en") {
    const titles = {
      laps_secret_read: `${amount} LAPS passwords are readable`,
      gmsa_secret_read: `${amount} gMSA passwords are readable`,
      directory_replication_read: `${amount} domains expose replication rights`,
      password_reset: `${amount} account passwords can be reset`,
      group_membership_write: `Membership of ${amount} groups can be changed`,
      spn_write: `SPNs on ${amount} accounts can be changed`,
      account_control_write: `Account-control settings on ${amount} targets can be changed`,
      key_credential_write: `Key Credentials on ${amount} targets can be changed`,
      rbcd_write: `RBCD delegation on ${amount} computers can be changed`,
      dacl_write: `DACLs on ${amount} objects can be changed`,
      owner_write: `Owners of ${amount} objects can be changed`,
      object_full_control: `${amount} objects expose full control`,
      object_property_write: `Properties on ${amount} objects can be changed`,
      object_delete: `${amount} objects can be deleted`,
      child_create: `Child objects can be created on ${amount} targets`,
      child_delete: `Child objects can be deleted on ${amount} targets`,
    };
    return titles[capability.capability_id] ?? `${amount} targets expose this AD action`;
  }
  const titles = {
    laps_secret_read: `${amount} LAPS parolası okunabiliyor`,
    gmsa_secret_read: `${amount} gMSA parolası okunabiliyor`,
    directory_replication_read: `${amount} domain için replication hakkı bulunuyor`,
    password_reset: `${amount} hesabın parolası sıfırlanabilir`,
    group_membership_write: `${amount} grubun üyeliği değiştirilebilir`,
    spn_write: `${amount} hesabın SPN değeri değiştirilebilir`,
    account_control_write: `${amount} hedefin hesap denetimi değiştirilebilir`,
    key_credential_write: `${amount} hedefin Key Credential değeri değiştirilebilir`,
    rbcd_write: `${amount} bilgisayarın RBCD delegasyonu değiştirilebilir`,
    dacl_write: `${amount} nesnenin DACL'i değiştirilebilir`,
    owner_write: `${amount} nesnenin sahibi değiştirilebilir`,
    object_full_control: `${amount} nesnede tam kontrol yetkisi görünüyor`,
    object_property_write: `${amount} nesnenin özellikleri değiştirilebilir`,
    object_delete: `${amount} nesne silinebilir`,
    child_create: `${amount} hedefte alt nesne oluşturulabilir`,
    child_delete: `${amount} hedefte alt nesne silinebilir`,
  };
  if (titles[capability.capability_id]) return titles[capability.capability_id];
  if (evidenceState === "verified") return `${amount} hedefte AD eylemi doğrulandı`;
  if (evidenceState === "unresolved") return `${amount} hedefte AD yetkisi kesinleştirilemedi`;
  return `${amount} hedefte AD yetkisine işaret eden ACL bulundu`;
}

function aggregateSubjectCount(capability) {
  const amount = Number(capability.aggregate_count).toLocaleString(numberLocale());
  const subjectType = String(capability.subject_type ?? "").toLowerCase();
  const labels = currentLanguage === "en"
    ? {
      user: `${amount} user objects`,
      group: `${amount} group objects`,
      computer: `${amount} computer objects`,
      organizationalunit: `${amount} organizational units`,
      grouppolicycontainer: `${amount} GPOs`,
      domaindns: `${amount} domain objects`,
    }
    : {
      user: `${amount} kullanıcı nesnesi`,
      group: `${amount} grup nesnesi`,
      computer: `${amount} bilgisayar nesnesi`,
      organizationalunit: `${amount} organizasyon birimi`,
      grouppolicycontainer: `${amount} GPO`,
      domaindns: `${amount} domain nesnesi`,
    };
  return labels[subjectType] ?? (currentLanguage === "en"
    ? `${amount} directory objects`
    : `${amount} directory nesnesi`);
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
    const uniqueTargets = new Map();
    for (const item of items) {
      const subject = String(item.subject ?? "").trim();
      const targetDn = String(item.target_dn ?? "").trim();
      const key = `${subject}\u0000${targetDn}`;
      if (subject !== "" && !uniqueTargets.has(key)) {
        uniqueTargets.set(key, {subject, target_dn: targetDn || null});
      }
    }
    const targets = [...uniqueTargets.values()]
      .sort((left, right) => left.subject.localeCompare(right.subject));
    return {...items[0], aggregate_count: items.length, targets};
  });
}

function capabilityPath(capability, identityPrincipal) {
  const path = document.createElement("div");
  path.className = "identity-access-path";
  const values = [identityPrincipal];
  const via = String(capability.via_principal ?? "").trim();
  if (via !== "" && via.toLocaleLowerCase() !== String(identityPrincipal).toLocaleLowerCase()) {
    values.push(via);
  }
  values.push(
    Number(capability.aggregate_count) > 1
      ? (currentLanguage === "en"
        ? `${Number(capability.aggregate_count).toLocaleString(numberLocale())} targets`
        : `${Number(capability.aggregate_count).toLocaleString(numberLocale())} hedef`)
      : displayValue(capability.subject),
  );
  values.forEach((value, index) => {
    if (index > 0) {
      const arrow = document.createElement("span");
      arrow.className = "identity-path-arrow";
      arrow.textContent = "→";
      path.append(arrow);
    }
    const node = document.createElement("span");
    node.className = `identity-path-node ${index === values.length - 1 ? "is-target" : ""}`.trim();
    node.textContent = displayValue(value);
    path.append(node);
  });
  return path;
}

function capabilityCard(capability, identityPrincipal) {
  const card = document.createElement("article");
  card.className = "identity-capability";
  const header = document.createElement("header");
  header.className = "identity-capability-header";
  const title = document.createElement("h4");
  title.textContent = Number(capability.aggregate_count) > 1
    ? aggregateCapabilityTitle(capability)
    : capabilityTitle(capability);
  const evidenceKey = String(capability.evidence_state ?? "acl_indicated").toLowerCase();
  card.classList.add(`is-${evidenceKey.replaceAll("_", "-")}`);
  header.append(title);
  const evidence = document.createElement("span");
  evidence.className = `identity-evidence is-${evidenceKey.replaceAll("_", "-")}`;
  evidence.textContent = identityLabel(
    IDENTITY_EVIDENCE_LABELS,
    evidenceKey,
    displayValue(evidenceKey),
  );
  header.append(evidence);

  const summaryLayout = document.createElement("div");
  summaryLayout.className = "identity-capability-summary-layout";
  const rights = Array.isArray(capability.rights) ? capability.rights : [];
  if (rights.length > 0) {
    const rightList = document.createElement("div");
    rightList.className = "identity-summary-rights";
    for (const right of rights) {
      const item = document.createElement("span");
      item.className = "identity-right";
      item.textContent = currentLanguage !== "en"
          && ["Tüm extended rights", "Tüm genişletilmiş haklar"].includes(right)
        ? "Tüm genişletilmiş haklar"
        : displayValue(right);
      rightList.append(item);
    }
    summaryLayout.append(rightList);
  }
  const summary = document.createElement("p");
  summary.className = "identity-capability-summary";
  appendHighlightedCapabilitySummary(
    summary,
    capabilitySummary(capability, identityPrincipal),
    capability,
    identityPrincipal,
  );
  summaryLayout.append(summary);
  card.append(header, capabilityPath(capability, identityPrincipal));
  card.append(summaryLayout);

  const targetDn = capability.target_dn;
  if (Number(capability.aggregate_count) <= 1
      && typeof targetDn === "string" && targetDn !== "") {
    const metadata = document.createElement("div");
    metadata.className = "identity-capability-meta";
    const row = document.createElement("div");
    row.className = "identity-meta-row";
    row.append(document.createTextNode(`${currentLanguage === "en" ? "Target DN" : "Hedef DN"}: `));
    const targetValue = document.createElement("code");
    targetValue.textContent = targetDn;
    row.append(targetValue);
    metadata.append(row);
    card.append(metadata);
  }

  if (Number(capability.aggregate_count) > 1) {
    const targets = document.createElement("details");
    targets.className = "identity-capability-targets";
    const targetsSummary = document.createElement("summary");
    targetsSummary.textContent = aggregateTargetLabel(capability);
    const targetList = document.createElement("div");
    targetList.className = "identity-capability-target-list";
    for (const target of capability.targets ?? []) {
      const item = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = displayValue(target?.subject);
      item.append(name);
      if (typeof target?.target_dn === "string" && target.target_dn !== "") {
        const dn = document.createElement("code");
        dn.textContent = target.target_dn;
        item.append(dn);
      }
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
    nextStep.append(label);
    appendBrandedIdentityText(nextStep, nextStepValue);
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
  identityTabCount.textContent = capabilityGroups.length.toLocaleString(numberLocale());

  identityAccessStatus.textContent = identityLabel(
    IDENTITY_STATUS_LABELS,
    status,
    displayValue(status),
  );
  identityAccessStatus.className = `status-value ${statusTone(status)}`.trim();
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
  const writeProbeEnabled = report.write_probe_enabled === true;
  const capabilitySection = resultSection(
    currentLanguage === "en" ? "Identity-scoped AD access" : "Kimliğin AD erişimleri",
    writeProbeEnabled
      ? (currentLanguage === "en"
        ? "Live reads and supported LDAP write requests were tested; unsupported writes remain ACL-backed."
        : "Canlı okumalar ve desteklenen LDAP yazma istekleri denendi; diğer yazmalar ACL kanıtı olarak kaldı.")
      : (currentLanguage === "en"
        ? "Live reads are verified; write actions are shown from ACL evidence without changing directory state."
        : "Canlı okumalar doğrulanır; yazma eylemleri directory durumu değiştirilmeden ACL kanıtıyla gösterilir."),
  );
  const capabilityList = document.createElement("div");
  capabilityList.className = "identity-capability-list";
  if (capabilities.length === 0) {
    const empty = document.createElement("div");
    empty.className = "identity-no-capability";
    const title = document.createElement("strong");
    title.textContent = currentLanguage === "en"
      ? "No actionable AD access was found"
      : "Eyleme dönüşen AD erişimi bulunamadı";
    const copy = document.createElement("p");
    copy.textContent = currentLanguage === "en"
      ? "No readable managed password or matching actionable ACL right was found for this identity."
      : "Bu kimlik için okunabilir yönetilen parola veya eyleme dönüşen bir ACL hakkı bulunamadı.";
    empty.append(title, copy);
    capabilityList.append(empty);
  } else {
    for (const capability of capabilityGroups) {
      capabilityList.append(capabilityCard(capability, report.identity?.principal));
    }
  }
  capabilitySection.append(capabilityList);

  layout.append(capabilitySection);
  identityAccessContent.append(layout);
}

export {
  configureIdentityAccess,
  currentIdentityAccess,
  renderIdentityAccess,
};
