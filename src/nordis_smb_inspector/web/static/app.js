"use strict";

const body = document.body;
const languageSelect = document.querySelector("#language-select");
const workspaceNavigationItems = [...document.querySelectorAll("[data-workspace-view]")];
const scanWorkspace = document.querySelector("#scan-workspace");
const hashToolsWorkspace = document.querySelector("#hash-tools-workspace");
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
const historyDeleteDialog = document.querySelector("#history-delete-dialog");
const closeHistoryDeleteButton = document.querySelector("#close-history-delete");
const cancelHistoryDeleteButton = document.querySelector("#cancel-history-delete");
const confirmHistoryDeleteButton = document.querySelector("#confirm-history-delete");
const historyDeleteName = document.querySelector("#history-delete-name");
const historyDeleteMeta = document.querySelector("#history-delete-meta");
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
const historySelectionDetail = document.querySelector("#history-selection-detail");
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
let pendingHistoryDeleteKey = null;
let selectedHistoryKey = null;
let pendingScanInputs = null;
const scanInputSnapshots = new Map();
let selectedHashCandidateKey = null;
let hashWordlistUpload = null;
let hashWordlistName = "";
let hashWordlistUploading = false;
let hashToolsState = {tools: [], job: null, wordlist: null};
let hashToolsAvailabilityError = null;
let hashToolsRefreshTimer = null;
let currentScanActive = false;

const HISTORY_KEY = "nordis.scan-history.v1";

const CCACHE_MAX_BYTES = 1024 * 1024;
const WORDLIST_MAX_BYTES = 1024 * 1024;
const HASH_WORDLIST_MAX_BYTES = 256 * 1024 * 1024;
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
const OK_STATUS = /(?:OPEN|READY|SUCCESS|AUTHENTICATED|DOĞRULANDI|KERBEROS|NTLM|COMPLETED|PARTIAL_ACCESS|CONNECTED|LISTABLE|READABLE)/u;
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
  artifact: "Dosya imzası",
  high: "Yüksek",
  medium: "Orta",
  low: "Düşük",
  allowed: "İzin var",
  denied: "Reddedildi",
  unknown: "Bilinmiyor",
  error: "Hata",
};
const FINDING_METHOD_LABELS = {
  wordlist: "Arama terimi",
  pattern: "Otomatik tespit",
  artifact: "Dosya imzası",
};
const EN_FINDING_METHOD_LABELS = {
  wordlist: "Search term",
  pattern: "Automatic detection",
  artifact: "File signature",
};
const FINDING_RULE_LABELS = {
  "cloud-access-key": "Bulut erişim anahtarı",
  "jwt-token": "JWT oturum tokenı",
  "private-key-header": "Özel anahtar başlangıcı",
  "authorization-bearer": "Bearer token",
  "authorization-basic": "Basic kimlik doğrulama değeri",
  "credential-url": "URL içindeki kimlik bilgisi",
  "secret-assignment": "Parola veya token",
  "connection-string-password": "Veritabanı bağlantı parolası",
  "gpp-cpassword": "Group Policy cpassword",
  "kerberos-tgs-artifact": "Kerberos TGS-REP verisi",
  "kerberos-asrep-artifact": "Kerberos AS-REP verisi",
  "kerberos-preauth-artifact": "Kerberos ön kimlik doğrulama verisi",
  "kerberos-db-key": "Kerberos KDC veritabanı anahtarı",
  "windows-nt-hash": "NTLM hash",
  "kerberos-rc4-key": "Kerberos RC4 anahtarı",
  "kerberos-aes128-key": "Kerberos AES-128 anahtarı",
  "kerberos-aes256-key": "Kerberos AES-256 anahtarı",
  "kerberos-des-key": "Kerberos DES anahtarı",
  "lm-nt-hash-pair": "LM/NT hash çifti",
  "credential-dump-line": "Hesap RID'si ve parola hash'leri",
  "netntlmv1-response": "NetNTLMv1 yanıtı",
  "netntlmv2-response": "NetNTLMv2 yanıtı",
  "dcc2-hash": "Önbelleğe alınmış etki alanı hash'i (DCC2)",
  "unix-password-hash": "Unix parola hash'i",
  "modern-password-hash": "Bcrypt veya Argon2 hash'i",
  "github-token-prefix": "GitHub erişim tokenı",
  "github-fine-grained-token": "GitHub ayrıntılı erişim tokenı",
  "gitlab-token-prefix": "GitLab erişim tokenı",
  "slack-token-prefix": "Slack tokenı",
  "stripe-secret-key": "Stripe gizli anahtarı",
  "sendgrid-api-key": "SendGrid API anahtarı",
  "google-api-key": "Google API anahtarı",
  "npm-token-prefix": "npm erişim tokenı",
  "pypi-token-prefix": "PyPI API tokenı",
  "huggingface-token-prefix": "Hugging Face tokenı",
  "vault-token-prefix": "Vault tokenı",
  "private-token-header": "Özel erişim tokenı başlığı",
  "cookie-secret-assignment": "Oturum çerezi değeri",
  "netrc-credential": "netrc kimlik bilgisi",
  "aws-secret-access-key": "AWS gizli erişim anahtarı",
  "docker-registry-auth": "Docker kayıt deposu kimlik bilgisi",
  "ansible-vault-artifact": "Ansible Vault verisi",
  "sops-encrypted-artifact": "SOPS şifreli değeri",
  "windows-managed-password": "Windows yönetilen parola alanı",
  "age-encrypted-file": "Age ile şifrelenmiş dosya",
  "kerberos-ccache-file": "Kerberos kimlik bilgisi önbelleği (CCache)",
  "kerberos-keytab-file": "Kerberos anahtar tablosu (keytab)",
  "kerberos-kirbi-file": "Kerberos bilet dosyası (KIRBI)",
};
const EN_FINDING_RULE_LABELS = {
  "cloud-access-key": "Cloud access key",
  "jwt-token": "JWT session token",
  "private-key-header": "Private key header",
  "authorization-bearer": "Bearer token",
  "authorization-basic": "Basic authentication value",
  "credential-url": "Credential embedded in URL",
  "secret-assignment": "Password or token",
  "connection-string-password": "Database connection password",
  "gpp-cpassword": "Group Policy cpassword",
  "kerberos-tgs-artifact": "Kerberos TGS-REP material",
  "kerberos-asrep-artifact": "Kerberos AS-REP material",
  "kerberos-preauth-artifact": "Kerberos pre-auth material",
  "kerberos-db-key": "Kerberos KDC database key",
  "windows-nt-hash": "NTLM hash",
  "kerberos-rc4-key": "Kerberos RC4 key",
  "kerberos-aes128-key": "Kerberos AES-128 key",
  "kerberos-aes256-key": "Kerberos AES-256 key",
  "kerberos-des-key": "Kerberos DES key",
  "lm-nt-hash-pair": "LM/NT hash pair",
  "credential-dump-line": "Account RID/hash record",
  "netntlmv1-response": "NetNTLMv1 response",
  "netntlmv2-response": "NetNTLMv2 response",
  "dcc2-hash": "Cached domain credential",
  "unix-password-hash": "Unix password hash",
  "modern-password-hash": "Bcrypt or Argon2 hash",
  "github-token-prefix": "GitHub access token",
  "github-fine-grained-token": "GitHub fine-grained token",
  "gitlab-token-prefix": "GitLab access token",
  "slack-token-prefix": "Slack token",
  "stripe-secret-key": "Stripe secret key",
  "sendgrid-api-key": "SendGrid API key",
  "google-api-key": "Google API key",
  "npm-token-prefix": "npm access token",
  "pypi-token-prefix": "PyPI API token",
  "huggingface-token-prefix": "Hugging Face token",
  "vault-token-prefix": "Vault token",
  "private-token-header": "Private access token header",
  "cookie-secret-assignment": "Session cookie value",
  "netrc-credential": "netrc credential",
  "aws-secret-access-key": "AWS secret access key",
  "docker-registry-auth": "Docker registry credential",
  "ansible-vault-artifact": "Ansible Vault material",
  "sops-encrypted-artifact": "SOPS encrypted value",
  "windows-managed-password": "Windows managed password field",
  "age-encrypted-file": "Age encrypted file",
  "kerberos-ccache-file": "Kerberos credential cache file",
  "kerberos-keytab-file": "Kerberos keytab file",
  "kerberos-kirbi-file": "Kerberos ticket file",
};
const HASH_FORMAT_LABELS = {
  ntlm: "NTLM hash",
  lm: "LM hash",
  netntlmv1: "NetNTLMv1 yanıtı",
  netntlmv2: "NetNTLMv2 yanıtı",
  dcc2: "DCC2 etki alanı hash’i",
  md5crypt: "Unix MD5crypt hash’i",
  sha256crypt: "Unix SHA-256 crypt hash’i",
  sha512crypt: "Unix SHA-512 crypt hash’i",
  bcrypt: "Bcrypt hash’i",
  argon2: "Argon2 hash’i",
  kerberos_tgs_etype17: "Kerberos TGS-REP · etype 17",
  kerberos_tgs_etype18: "Kerberos TGS-REP · etype 18",
  kerberos_tgs_etype23: "Kerberos TGS-REP · etype 23",
  kerberos_asrep_etype17: "Kerberos AS-REP · etype 17",
  kerberos_asrep_etype18: "Kerberos AS-REP · etype 18",
  kerberos_asrep_etype23: "Kerberos AS-REP · etype 23",
  kerberos_preauth_etype17: "Kerberos ön kimlik doğrulama · etype 17",
  kerberos_preauth_etype18: "Kerberos ön kimlik doğrulama · etype 18",
  kerberos_preauth_etype23: "Kerberos ön kimlik doğrulama · etype 23",
  kerberos_db_etype17: "Kerberos KDC veritabanı · etype 17",
  kerberos_db_etype18: "Kerberos KDC veritabanı · etype 18",
};
const EN_HASH_FORMAT_LABELS = {
  ntlm: "NTLM hash",
  lm: "LM hash",
  netntlmv1: "NetNTLMv1 response",
  netntlmv2: "NetNTLMv2 response",
  dcc2: "DCC2 domain hash",
  md5crypt: "Unix MD5crypt hash",
  sha256crypt: "Unix SHA-256 crypt hash",
  sha512crypt: "Unix SHA-512 crypt hash",
  bcrypt: "Bcrypt hash",
  argon2: "Argon2 hash",
  kerberos_tgs_etype17: "Kerberos TGS-REP · etype 17",
  kerberos_tgs_etype18: "Kerberos TGS-REP · etype 18",
  kerberos_tgs_etype23: "Kerberos TGS-REP · etype 23",
  kerberos_asrep_etype17: "Kerberos AS-REP · etype 17",
  kerberos_asrep_etype18: "Kerberos AS-REP · etype 18",
  kerberos_asrep_etype23: "Kerberos AS-REP · etype 23",
  kerberos_preauth_etype17: "Kerberos pre-auth · etype 17",
  kerberos_preauth_etype18: "Kerberos pre-auth · etype 18",
  kerberos_preauth_etype23: "Kerberos pre-auth · etype 23",
  kerberos_db_etype17: "Kerberos KDC database · etype 17",
  kerberos_db_etype18: "Kerberos KDC database · etype 18",
};
const HASH_JOB_LABELS = {
  idle: "Hazır",
  running: "Çalışıyor",
  cancelling: "Durduruluyor",
  cracked: "Parola bulundu",
  exhausted: "Eşleşme yok",
  timed_out: "Süre doldu",
  cancelled: "Durduruldu",
  failed: "Başarısız",
};
const EN_HASH_JOB_LABELS = {
  idle: "Ready",
  running: "Running",
  cancelling: "Stopping",
  cracked: "Password found",
  exhausted: "No match",
  timed_out: "Time limit reached",
  cancelled: "Stopped",
  failed: "Failed",
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
  wordlist: "Wordlist match", pattern: "Pattern match", artifact: "File signature",
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
const TR_CATEGORY_LABELS = {
  "Cloud / SaaS": "Bulut / SaaS", "Oturum tokenı": "Oturum tokenı",
  "Kriptografik anahtar": "Kriptografik anahtar", "Kimlik bilgisi": "Kimlik bilgisi",
  Veritabanı: "Veritabanı", Yapılandırma: "Yapılandırma", "Windows / AD": "Windows / AD",
  "Credential artifact": "Kimlik doğrulama verisi", "Source control": "Kaynak kod yönetimi",
  "Ödeme servisi": "Ödeme servisi", "Developer tooling": "Geliştirici araçları",
  Infrastructure: "Altyapı", "Container tooling": "Konteyner araçları",
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
  "Kaynak": "Source", "Bulgu": "Finding",
  "Bulgu sınıfı": "Finding class", "Eşleşme gücü": "Match strength",
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
    "Tarama girdileri ve tamamlanan sonuçlar bu tarayıcıda saklanır.": "Scan inputs and completed results are stored in this browser.",
    "Tarama girdileri": "Scan inputs",
    "Girdileri görmek için bir tarama seç.": "Select a scan to view its inputs.",
    "Sonuçları aç": "Open results",
    "Tarama ayarlarını göster": "Show scan settings",
    "Hedef listesi": "Target list",
    "Kimlik türü": "Credential type",
    "Kimlik doğrulama modu": "Authentication mode",
    "Girilen parola": "Submitted password",
    "Girilen NT hash": "Submitted NT hash",
    "CCache dosya adı": "CCache file name",
    "CCache dosya boyutu": "CCache file size",
    "Dosya yolu": "File path",
    "Tarayıcı tam dosya yolunu paylaşmaz.": "The browser does not expose the full file path.",
    "Dahili wordlist": "Built-in wordlist",
    "Ek terimler": "Additional terms",
    "Veri kalıpları": "Data patterns",
    "Kullanıldı": "Used",
    "Dahil edildi": "Included",
    "Dahil edilmedi": "Not included",
    "Bu kayıtta saklanmadı.": "Not retained in this record.",
    "Göster": "Show",
    "Gizle": "Hide",
    "Parola ve hash bu tarayıcı geçmişinde yerel olarak saklanır.": "Passwords and hashes are stored locally in this browser history.",
    "İçerik arama terimleri": "Content search terms",
    "TXT içe aktar": "Import TXT",
    "Kaydet": "Save",
    "0 hedef": "0 targets",
    "0 kayıt": "0 entries",
    "0 bulgu": "0 findings",
    "— kayıt": "— entries",
    "Ayrıntı için bir hedef seç.": "Select a target to view details.",
    "Ayrıntı için bir kayıt seç.": "Select an entry to view details.",
    "Ayrıntı için bir bulgu seç.": "Select a finding to view details.",
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
    "Taramayı sil": "Delete scan",
    "Bu tarama geçmişten kalıcı olarak silinecek. Bu işlem geri alınamaz.": "This scan will be permanently deleted from history. This action cannot be undone.",
    "Vazgeç": "Cancel",
    "Geçmişten sil": "Delete from history",
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
    "Çalışma alanları": "Workspaces",
    "SMB Tarama": "SMB Scan",
    "Hash Araçları": "Hash Tools",
    "Uygun bulguyu seçtiğin yerel araca aktarır. Bulgu ve wordlist dış servise gönderilmez.": "Sends the selected finding to a local tool. Findings and wordlists are never sent to an external service.",
    "Yerel araç durumu": "Local tool status",
    "Yerel araçlar kontrol ediliyor.": "Checking local tools.",
    "Çözülebilir bulgular": "Crackable findings",
    "Yalnız desteklenen çevrimdışı parola hash’leri gösterilir.": "Only supported offline password hashes are shown.",
    "Uygun bulgu yok.": "No compatible findings.",
    "Çalıştırma": "Run",
    "Önce bir bulgu seç.": "Select a finding first.",
    "Hazır": "Ready",
    "Yerel araç": "Local tool",
    "Süre sınırı": "Time limit",
    "Kullanılabilir araç yok": "No available tools",
    "30 saniye": "30 seconds",
    "2 dakika": "2 minutes",
    "5 dakika": "5 minutes",
    "TXT seç": "Select TXT",
    "Çalıştır": "Run",
    "Durdur": "Stop",
    "Bulunan parola": "Recovered password",
    "Sonuç yalnız bu uygulama oturumunda bellekte tutulur.": "The result is kept in memory for this application session only.",
    "Hash Araçlarına gönder": "Send to Hash Tools",
    "Kullanıma hazır": "Available",
    "Bulunamadı": "Not found",
    "Araç durumu alınamadı.": "Could not check local tool status.",
    "Hash Araçları backend’i bulunamadı. Uygulamayı yeniden başlat.": "The Hash Tools backend is unavailable. Restart the application.",
    "Seçilen bulguyla uyumlu yüklü araç yok.": "No installed tool supports the selected finding.",
    "Wordlist dosyası seç.": "Select a wordlist file.",
    "Yalnız .txt wordlist seçilebilir.": "Only a .txt wordlist can be selected.",
    "Wordlist en fazla 256 MiB olabilir.": "The wordlist can be at most 256 MiB.",
    "Wordlist boş olamaz.": "The wordlist cannot be empty.",
    "Wordlist okunamadı.": "The wordlist could not be read.",
    "Wordlist yükleniyor.": "Uploading wordlist.",
    "Wordlist yüklendi.": "Wordlist uploaded.",
    "Yüklenen wordlist": "Uploaded wordlist",
    "İşlem başlatılıyor.": "Starting the job.",
    "Durdurma isteği gönderildi.": "Stop requested.",
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
    ["Yazma", record.writeAccess],
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
    ["target", "share", "path", "type", "status", "size", "detail"],
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
  hashWordlistFile.disabled = jobActive || currentScanActive || hashWordlistUploading;
  startHashToolButton.disabled = jobActive
    || currentScanActive
    || hashWordlistUploading
    || !entry
    || !toolAvailable
    || typeof hashWordlistUpload?.upload_id !== "string";
  cancelHashToolButton.disabled = !jobActive;
}

function sendFindingToHashTools(record) {
  if (hashJobIsActive()) {
    activateWorkspace("hash-tools");
    return;
  }
  const recordKey = findingKey(record);
  const candidate = record.auditCandidates[0];
  if (candidate) {
    selectedHashCandidateKey = `${recordKey}\u001e${candidate.id}`;
  }
  activateWorkspace("hash-tools");
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

function scanSearchOptions() {
  return {
    use_default: true,
    additional_terms: additionalSearchTerms(),
    detect_patterns: detectPatternsInput.checked,
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
    credential: storedCredential,
    search: {
      use_default: search.use_default,
      additional_terms: [...search.additional_terms],
      additional_terms_input: additionalTermsInput.value.trim(),
      detect_patterns: search.detect_patterns,
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
    auto: "Auto (Kerberos öncelikli)",
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
  const scanSection = historyDetailSection("Hedefler", [
    ["Tarama adı", displayValue(item.name), "detail-code"],
    ["Hedef listesi", retainedHistoryValue(targetList), "detail-code"],
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
  const searchSection = historyDetailSection("İçerik arama", [
    ["Dahili wordlist", !searchRetained
      ? uiText("Bu kayıtta saklanmadı.")
      : uiText(search.use_default ? "Kullanıldı" : "Dahil edilmedi")],
    ["Ek terimler", terms, "detail-code"],
    ["Veri kalıpları", !searchRetained
      ? uiText("Bu kayıtta saklanmadı.")
      : uiText(search.detect_patterns ? "Dahil edildi" : "Dahil edilmedi")],
  ]);

  const content = [heading, counts, scanSection, credentialSection, searchSection];
  if (credential.kind === "password" || credential.kind === "nt_hash") {
    const note = document.createElement("p");
    note.className = "history-detail-note";
    note.textContent = uiText("Parola ve hash bu tarayıcı geçmişinde yerel olarak saklanır.");
    content.push(note);
  }
  historySelectionDetail.replaceChildren(...content);
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
  activateResultTab("findings");
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
  selectedHistoryKey = state.scan_id;
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
  currentScanActive = active;
  startScanButton.disabled = active;
  cancelScanButton.disabled = !active || status === "cancelling";
  syncHashToolControls();
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

for (const item of workspaceNavigationItems) {
  item.addEventListener("click", () => activateWorkspace(item.dataset.workspaceView));
}

openWordlistsButton.addEventListener("click", async () => {
  await refreshWordlists();
  wordlistDialog.showModal();
});
closeWordlistsButton.addEventListener("click", () => wordlistDialog.close());
wordlistDialog.addEventListener("click", (event) => {
  if (event.target === wordlistDialog) wordlistDialog.close();
});
closeHistoryDeleteButton.addEventListener("click", closeHistoryDeleteDialog);
cancelHistoryDeleteButton.addEventListener("click", closeHistoryDeleteDialog);
confirmHistoryDeleteButton.addEventListener("click", confirmHistoryItemDelete);
historyDeleteDialog.addEventListener("close", () => {
  pendingHistoryDeleteKey = null;
});
historyDeleteDialog.addEventListener("click", (event) => {
  if (event.target === historyDeleteDialog) closeHistoryDeleteDialog();
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
hashToolSelect.addEventListener("change", syncHashToolControls);
hashWordlistFile.addEventListener("change", loadHashWordlist);
startHashToolButton.addEventListener("click", startHashTool);
cancelHashToolButton.addEventListener("click", cancelHashTool);
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
activateWorkspace("scan");
activateResultTab("targets");
refreshSnapshot();
refreshResultPanels();
refreshWordlists();
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
