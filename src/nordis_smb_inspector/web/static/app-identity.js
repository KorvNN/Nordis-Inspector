"use strict";

import {currentLanguage, numberLocale} from "./app-i18n.js";

const identityAccessStatus = document.querySelector("#identity-access-status");
const identityAccessContent = document.querySelector("#identity-access-content");
const identityTabCount = document.querySelector("#identity-tab-count");
const identityTargetsDialog = document.querySelector("#identity-targets-dialog");
const identityTargetsHeading = document.querySelector("#identity-targets-heading");
const identityTargetsDescription = document.querySelector("#identity-targets-description");
const identityTargetsList = document.querySelector("#identity-targets-list");
const identityTargetsSearch = document.querySelector("#identity-targets-search");
const identityTargetsCount = document.querySelector("#identity-targets-count");
const identityTargetsEmpty = document.querySelector("#identity-targets-empty");
const identityTargetsNameHeading = document.querySelector("#identity-targets-name-heading");
const identityTargetsDnHeading = document.querySelector("#identity-targets-dn-heading");
const closeIdentityTargetsButton = document.querySelector("#close-identity-targets");
const cancelIdentityTargetsButton = document.querySelector("#cancel-identity-targets");

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
const CAPABILITY_CATEGORY_BY_ID = {
  laps_secret_read: "secret_access",
  gmsa_secret_read: "secret_access",
  directory_replication_read: "secret_access",
  password_reset: "account_control",
  spn_write: "account_control",
  account_control_write: "account_control",
  key_credential_write: "account_control",
  group_membership_write: "group_delegation",
  rbcd_write: "group_delegation",
};
const CAPABILITY_CATEGORY_ORDER = [
  "secret_access",
  "account_control",
  "group_delegation",
  "object_control",
];
const CAPABILITY_CATEGORY_LABELS = {
  tr: {
    all: "Tümü",
    secret_access: "Gizli veri erişimi",
    account_control: "Hesap kontrolü",
    group_delegation: "Grup ve delegasyon",
    object_control: "Nesne kontrolü",
  },
  en: {
    all: "All",
    secret_access: "Secret access",
    account_control: "Account control",
    group_delegation: "Groups and delegation",
    object_control: "Object control",
  },
};
const CAPABILITY_PRIORITY = {
  directory_replication_read: 0,
  laps_secret_read: 1,
  gmsa_secret_read: 2,
  password_reset: 3,
  key_credential_write: 4,
  group_membership_write: 5,
  rbcd_write: 6,
  spn_write: 7,
  account_control_write: 8,
  object_full_control: 9,
  dacl_write: 10,
  owner_write: 11,
  object_property_write: 12,
  all_extended_rights: 13,
  object_delete: 14,
  child_create: 15,
  child_delete: 16,
};
const EVIDENCE_PRIORITY = {
  verified: 0,
  acl_indicated: 1,
  inferred: 1,
  unresolved: 2,
};
const LEGACY_RIGHT_ALIASES = new Map([
  ["Nesne sahibi (implicit WriteDACL)", "WriteDacl (object owner)"],
  ["Tam kontrol (GenericAll)", "GenericAll"],
  ["Genel yazma (GenericWrite)", "GenericWrite"],
  ["DACL değiştirme", "WriteDacl"],
  ["Sahip değiştirme", "WriteOwner"],
  ["Nesneyi silme", "Delete"],
  ["Alt nesne oluşturma", "CreateChild"],
  ["Alt nesne silme", "DeleteChild"],
  ["Tüm özellikleri yazma", "WriteProperty"],
  ["Tüm extended rights", "AllExtendedRights"],
  ["Tüm genişletilmiş haklar", "AllExtendedRights"],
  ["All Extended Rights", "AllExtendedRights"],
]);

let displayValue;
let statusTone;
let identityAccessSnapshot = null;
let activeCapabilityCategory = "all";
let identityDialogTargets = [];

function configureIdentityAccess(dependencies) {
  ({displayValue, statusTone} = dependencies);
}

function currentIdentityAccess() {
  return identityAccessSnapshot;
}

function identityLabel(labels, key, fallback = key) {
  return labels[currentLanguage]?.[key] ?? fallback;
}

function capabilityCategory(capability) {
  return CAPABILITY_CATEGORY_BY_ID[capability.capability_id] ?? "object_control";
}

function capabilityCategoryLabel(category) {
  return CAPABILITY_CATEGORY_LABELS[currentLanguage]?.[category] ?? category;
}

function compareCapabilities(left, right) {
  const leftEvidence = String(left.evidence_state ?? "acl_indicated").toLowerCase();
  const rightEvidence = String(right.evidence_state ?? "acl_indicated").toLowerCase();
  const evidenceDifference = (EVIDENCE_PRIORITY[leftEvidence] ?? 99)
    - (EVIDENCE_PRIORITY[rightEvidence] ?? 99);
  if (evidenceDifference !== 0) return evidenceDifference;
  const actionDifference = (CAPABILITY_PRIORITY[left.capability_id] ?? 99)
    - (CAPABILITY_PRIORITY[right.capability_id] ?? 99);
  if (actionDifference !== 0) return actionDifference;
  const countDifference = Number(right.aggregate_count ?? 1)
    - Number(left.aggregate_count ?? 1);
  if (countDifference !== 0) return countDifference;
  return capabilityTitle(left).localeCompare(capabilityTitle(right));
}

function capabilityFilterToolbar(capabilities) {
  const toolbar = document.createElement("div");
  toolbar.className = "identity-capability-filters";
  toolbar.setAttribute("role", "toolbar");
  toolbar.setAttribute(
    "aria-label",
    currentLanguage === "en" ? "Filter AD findings by category" : "AD bulgularını kategoriye göre filtrele",
  );
  const categories = ["all", ...CAPABILITY_CATEGORY_ORDER.filter((category) => (
    capabilities.some((capability) => capabilityCategory(capability) === category)
  ))];
  if (!categories.includes(activeCapabilityCategory)) activeCapabilityCategory = "all";
  for (const category of categories) {
    const count = category === "all"
      ? capabilities.length
      : capabilities.filter((capability) => capabilityCategory(capability) === category).length;
    const button = document.createElement("button");
    button.type = "button";
    button.className = `identity-category-filter ${category === activeCapabilityCategory ? "is-active" : ""}`.trim();
    button.setAttribute("aria-pressed", String(category === activeCapabilityCategory));
    button.append(document.createTextNode(capabilityCategoryLabel(category)));
    const countNode = document.createElement("strong");
    countNode.textContent = count.toLocaleString(numberLocale());
    button.append(countNode);
    button.addEventListener("click", () => {
      if (activeCapabilityCategory === category) return;
      activeCapabilityCategory = category;
      renderIdentityAccess(identityAccessSnapshot);
    });
    toolbar.append(button);
  }
  return toolbar;
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
  return principal;
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
  const principalAccount = principal
    .slice(principal.lastIndexOf("\\") + 1)
    .split("@", 1)[0];
  const via = String(capability.via_principal ?? "").trim();
  const viaIsActor = via !== "" && [
    principal,
    principalAccount,
    actor.toLowerCase(),
  ].includes(via.toLowerCase());
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

  const account = actor;
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

function capabilityRightNames(capability) {
  return (Array.isArray(capability.rights) ? capability.rights : [])
    .map((right) => {
      const value = String(right);
      const alias = LEGACY_RIGHT_ALIASES.get(value);
      if (alias) return alias;
      if (value.startsWith("Alt nesne oluşturma (")) {
        return `CreateChild (${value.slice("Alt nesne oluşturma (".length)}`;
      }
      if (value.startsWith("Alt nesne silme (")) {
        return `DeleteChild (${value.slice("Alt nesne silme (".length)}`;
      }
      return displayValue(value);
    });
}

function aggregateTargetLabel(capability) {
  const count = Number(capability.aggregate_count);
  const amount = count.toLocaleString(numberLocale());
  const subjectType = String(capability.subject_type ?? "").toLowerCase();
  if (currentLanguage === "en") return `View ${amount} targets`;
  const labels = {
    user: `${amount} kullanıcıyı görüntüle`,
    group: `${amount} grubu görüntüle`,
    computer: `${amount} bilgisayarı görüntüle`,
    gmsa: `${amount} gMSA hesabını görüntüle`,
  };
  return labels[subjectType] ?? `${amount} hedefi görüntüle`;
}

function aggregateTargetDialogTitle(capability) {
  const subjectType = String(capability.subject_type ?? "").toLowerCase();
  const labels = currentLanguage === "en"
    ? {
      user: "Affected users",
      group: "Affected groups",
      computer: "Affected computers",
      organizationalunit: "Affected organizational units",
      grouppolicycontainer: "Affected GPOs",
    }
    : {
      user: "Etkilenen kullanıcılar",
      group: "Etkilenen gruplar",
      computer: "Etkilenen bilgisayarlar",
      organizationalunit: "Etkilenen organizasyon birimleri",
      grouppolicycontainer: "Etkilenen GPO'lar",
    };
  return labels[subjectType] ?? (currentLanguage === "en" ? "Affected targets" : "Etkilenen hedefler");
}

function closeIdentityTargetsDialog() {
  if (identityTargetsDialog.open) identityTargetsDialog.close();
}

function renderIdentityTargetRows() {
  const query = identityTargetsSearch.value.trim().toLocaleLowerCase();
  const visibleTargets = query === ""
    ? identityDialogTargets
    : identityDialogTargets.filter((target) => (
      `${target?.subject ?? ""} ${target?.target_dn ?? ""}`.toLocaleLowerCase().includes(query)
    ));
  identityTargetsList.replaceChildren();
  for (const target of visibleTargets) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const name = document.createElement("strong");
    name.textContent = displayValue(target?.subject);
    nameCell.append(name);
    const dnCell = document.createElement("td");
    if (typeof target?.target_dn === "string" && target.target_dn !== "") {
      const dn = document.createElement("code");
      dn.textContent = target.target_dn;
      dnCell.append(dn);
    } else {
      dnCell.textContent = "—";
    }
    row.append(nameCell, dnCell);
    identityTargetsList.append(row);
  }
  const total = identityDialogTargets.length.toLocaleString(numberLocale());
  const visible = visibleTargets.length.toLocaleString(numberLocale());
  identityTargetsCount.textContent = query === ""
    ? (currentLanguage === "en" ? `${total} records` : `${total} kayıt`)
    : (currentLanguage === "en" ? `${visible} of ${total}` : `${visible} / ${total}`);
  identityTargetsEmpty.hidden = visibleTargets.length !== 0;
}

function openIdentityTargetsDialog(capability) {
  identityDialogTargets = Array.isArray(capability.targets) ? capability.targets : [];
  identityTargetsHeading.textContent = aggregateTargetDialogTitle(capability);
  const rights = capabilityRightNames(capability);
  identityTargetsDescription.textContent = rights.length > 0
    ? rights.join(" · ")
    : capabilityTitle(capability);
  closeIdentityTargetsButton.setAttribute(
    "aria-label",
    currentLanguage === "en" ? "Close" : "Kapat",
  );
  cancelIdentityTargetsButton.textContent = currentLanguage === "en" ? "Close" : "Kapat";
  identityTargetsSearch.placeholder = currentLanguage === "en" ? "Search name or DN" : "Ad veya DN ara";
  identityTargetsSearch.setAttribute(
    "aria-label",
    currentLanguage === "en" ? "Search affected targets" : "Etkilenen hedeflerde ara",
  );
  identityTargetsNameHeading.textContent = currentLanguage === "en" ? "Object" : "Nesne";
  identityTargetsDnHeading.textContent = "Distinguished name";
  identityTargetsEmpty.textContent = currentLanguage === "en" ? "No matching targets." : "Eşleşen hedef yok.";
  identityTargetsSearch.value = "";
  renderIdentityTargetRows();
  identityTargetsDialog.showModal();
  identityTargetsSearch.focus();
}

function capabilityTargetButton(capability) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "identity-target-trigger";
  const label = document.createElement("span");
  label.textContent = aggregateTargetLabel(capability);
  const icon = document.createElement("span");
  icon.className = "identity-target-trigger-icon";
  icon.setAttribute("aria-hidden", "true");
  icon.textContent = "›";
  button.append(label, icon);
  button.addEventListener("click", () => openIdentityTargetsDialog(capability));
  return button;
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
  }).sort(compareCapabilities);
}

function capabilityCard(capability, identityPrincipal) {
  const card = document.createElement("article");
  card.className = "identity-capability";
  const header = document.createElement("header");
  header.className = "identity-capability-header";
  const heading = document.createElement("div");
  heading.className = "identity-capability-heading";
  const rights = capabilityRightNames(capability);
  if (rights.length > 0) {
    const rightList = document.createElement("div");
    rightList.className = "identity-heading-rights";
    for (const right of rights) {
      const item = document.createElement("span");
      item.className = "identity-right";
      item.textContent = right;
      rightList.append(item);
    }
    heading.append(rightList);
  } else {
    const fallbackTitle = document.createElement("h4");
    fallbackTitle.textContent = capabilityTitle(capability);
    heading.append(fallbackTitle);
  }
  if (Number(capability.aggregate_count) > 1) {
    heading.append(capabilityTargetButton(capability));
  }
  const evidenceKey = String(capability.evidence_state ?? "acl_indicated").toLowerCase();
  card.classList.add(`is-${evidenceKey.replaceAll("_", "-")}`);
  header.append(heading);
  const evidence = document.createElement("span");
  evidence.className = `identity-evidence is-${evidenceKey.replaceAll("_", "-")}`;
  evidence.textContent = identityLabel(
    IDENTITY_EVIDENCE_LABELS,
    evidenceKey,
    displayValue(evidenceKey),
  );
  header.append(evidence);

  const summary = document.createElement("p");
  summary.className = "identity-capability-summary";
  appendHighlightedCapabilitySummary(
    summary,
    capabilitySummary(capability, identityPrincipal),
    capability,
    identityPrincipal,
  );
  card.append(header, summary);

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
    capabilitySection.append(capabilityFilterToolbar(capabilityGroups));
    const visibleCapabilities = activeCapabilityCategory === "all"
      ? capabilityGroups
      : capabilityGroups.filter((capability) => (
        capabilityCategory(capability) === activeCapabilityCategory
      ));
    for (const capability of visibleCapabilities) {
      capabilityList.append(capabilityCard(capability, report.identity?.principal));
    }
  }
  capabilitySection.append(capabilityList);

  layout.append(capabilitySection);
  identityAccessContent.append(layout);
}

closeIdentityTargetsButton.addEventListener("click", closeIdentityTargetsDialog);
cancelIdentityTargetsButton.addEventListener("click", closeIdentityTargetsDialog);
identityTargetsSearch.addEventListener("input", renderIdentityTargetRows);

export {
  configureIdentityAccess,
  currentIdentityAccess,
  renderIdentityAccess,
};
