# Nordis SMB Inspector — Wordlist ve Kalıp Algılama

Durum: **Taslak v0.1**

## 1. İki bağımsız arama yöntemi

Araç iki yöntemi birlikte veya ayrı ayrı çalıştırabilir:

1. **Wordlist araması:** Kullanıcının seçtiği `.txt` listelerindeki kelime ve
   ifadeleri arar.
2. **Kalıp algılama:** Biçimi bilinen secret, token ve anahtarları kurallarla
   arar; ilgili satırda `password` gibi bir kelimenin geçmesi gerekmez.

Kalıp algılama wordlist oluşturmaz, wordlist'i değiştirmez ve kullanıcıdan bir
derleme işlemi yapmasını istemez.

## 2. Wordlist araması

Repo kategori bazlı normal metin listeleri sağlar:

```text
wordlists/content/
├── general.txt
├── turkish.txt
├── database.txt
├── cloud.txt
└── windows-ad.txt
```

Panel üzerinden:

- Bir veya daha fazla dahili liste seçilebilir.
- Listeler görüntülenebilir ve kalıcı olarak düzenlenebilir.
- Harici `.txt` listesi yüklenebilir.
- Yalnız mevcut taramaya özgü terimler eklenebilir.
- Birleşik liste taramadan önce görülebilir ve tekrarlar kaldırılır.

Varsayılan eşleşme case-insensitive alt metin aramasıdır. İsteğe bağlı
case-sensitive, tam kelime ve kullanıcı regex modu bulunur. Aynı dosyadaki ilk
sonuçta durulmaz; bütün eşleşmeler konumlarıyla gösterilir.

## 3. Kalıp algılama

Başlangıç kategorileri:

- Cloud ve SaaS API anahtarı/token biçimleri
- JWT ve benzeri oturum token'ları
- Private key ve sertifika anahtar blokları
- Veritabanı connection string'leri
- Basic authentication ve URL içindeki credential biçimleri
- Windows/AD yapılandırmalarındaki hassas alan-değer çiftleri
- `.env`, JSON, YAML, XML, INI ve PowerShell atamaları
- NT/LM hash, Kerberos ticket hash ve yaygın credential dump satır biçimleri
- Yüksek entropy'li Base64 veya hexadecimal olası secret değerleri

Web panelinde her kategori ayrı açılıp kapatılır. Entropy taraması daha fazla
false-positive üretebildiği için ayrı bir seçenek ve güven eşiğiyle sunulur.

### 3.1 Credential ve hash artifact kalıpları

Dosya içeriğinde en az şu biçimler algılanır:

- Kerberos TGS: `$krb5tgs$23$...`, `$krb5tgs$17$...`, `$krb5tgs$18$...`
- Kerberos AS-REP: `$krb5asrep$23$...`, `$krb5asrep$17$...`,
  `$krb5asrep$18$...`
- Kerberos pre-auth: `$krb5pa$23$...` ve desteklenen diğer etype gösterimleri
- Ham NT hash: 32 hexadecimal karakter; yalnız güvenilir alan/etiket bağlamıyla
- `LMHASH:NTHASH` çiftleri ve yaygın hesap/RID/hash satır yapıları
- NetNTLMv1/NetNTLMv2 challenge-response satır biçimleri
- Windows cached domain credential gösterimleri (`$DCC2$...` gibi)
- Unix crypt (`$1$`, `$5$`, `$6$`), bcrypt ve Argon2 hash gösterimleri
- Araçların dışa aktardığı diğer açıkça tanımlanabilen credential artifact'leri

Bu kalıplar yalnız dosyada bulunan materyali tespit edip gösterir. Araç bunları
kırmaz, doğrulamak için kullanmaz veya giriş credential alanına otomatik taşımaz.

Tek başına 32 hexadecimal karakter MD5, NT hash veya başka bir tanımlayıcı
olabilir. Bu nedenle ham 32-hex değeri yalnız `ntlm`, `nthash`, `password hash`
gibi yakın bağlam, bilinen dump satır yapısı veya kullanıcı tarafından seçilen
düşük güvenli geniş tarama modu varsa raporlanır. Bulguda tahmin edilen tür ve
güven seviyesi açıkça gösterilir.

## 4. Bulgu gösterimi

Her bulgu kaynağını açıkça belirtir:

```text
Dosya:      \\10.20.30.15\Finance\config.ini
Yöntem:     PATTERN
Kural:      generic-connection-string
Kategori:   Database
Güven:      High
Konum:      Satır 18
Eşleşme:    Server=db01;User Id=app;Password=PlainTextValue!
```

Yöntem değerleri:

- `WORDLIST`: Düz kelime/ifade eşleşmesi
- `PATTERN`: Tanımlı yapı veya token kalıbı eşleşmesi
- `ENTROPY`: Rastlantısallık eşiğine göre olası secret

Aynı satır hem wordlist hem pattern kuralıyla bulunursa arayüz tek satırı
gruplayabilir; hangi kuralların eşleştiği yine ayrı ayrı gösterilir.

## 5. Kural biçimi

Başlangıç secret rule corpus'u repo içine alınarak Nordis'in kategori ve kural
modeline dahil edilir. Harici bir secret-scanner binary'si veya çalışma zamanı
servisi kullanılmaz; bütün kurallar Nordis'in kendi tarama motoru tarafından
çalıştırılır.

Planlanan yapı:

```text
rules/
├── content/
│   ├── cloud-saas.toml
│   ├── api-tokens.toml
│   ├── private-keys.toml
│   ├── database.toml
│   ├── windows-ad.toml
│   └── credential-artifacts.toml
├── SOURCE_LOCK.yml          # Kaynak sürüm/commit ve checksum kayıtları
└── THIRD_PARTY_LICENSES.md
```

Bu dosyaların tümü birlikte **Nordis Detection Rules** adını taşır. Kurallar
proje geliştirilirken Nordis kimlikleri ve kategorileriyle bir kez hazırlanır;
yayınlanan uygulamada sabit gelir. Kullanıcı arayüzünde upstream ürün veya
kaynak adı gösterilmez.

Nordis kural motoru rule ID, regex, keywords, entropy, secret group ve allowlist
alanlarını destekler. Desteklenmeyen veya geçersiz bir özellik sessizce
atlanmaz; başlangıç doğrulamasında açık hata üretilir.

Her Nordis kuralı en az benzersiz kimlik, başlık, kategori, regex, güven seviyesi
ve pozitif/negatif test örnekleri taşır. Kurallar uygulama başlarken doğrulanır;
geçersiz kural taramayı başlatmaz ve panelde açıklanır.

## 6. Sabit rule setin hazırlanması

Wordlist ve kalıp kapsamı proje geliştirme aşamasında şu şekilde tamamlanır:

- Türkçe/İngilizce kategori listeleri proje içinde küratörlü tutulur.
- Başlangıç rule corpus'u lisansı uygun tek bir açık kaynak rule setinden alınır
  ve Nordis kategori/modeline dahil edilir.
- Tekrar, bozuk regex ve pozitif/negatif örnekler otomatik test edilir.
- Rule set ilk ürün sürümü için test edilip sabitlenir. Normal tarama sırasında
  güncelleme veya upstream senkronizasyonu yapılmaz.

Kural ayrımı:

- **Genel kurallar:** Cloud/SaaS token'ları, API anahtarları, JWT, private key,
  generic-secret ve entropy kalıpları
- **AD/SMB kuralları:** SMB/Windows/AD, GPP `cpassword`, Kerberos ticket hash,
  NTLM, DCC2 ve diğer credential artifact biçimleri
- **Nordis wordlist'leri:** Türkçe/İngilizce literal içerik terimleri ve bilinen
  SMB share adları

Alınan kaynağın sürümü/commit'i sabitlenir ve zorunlu lisans bildirimi yalnız
geliştiriciye yönelik üçüncü taraf bildirim dosyasında korunur. Birleşik rule
set proje sırasında tamamlanır; sonrasında harici güncelleme mekanizması sunulmaz.

Normal uygulama çalışırken harici secret-scanner binary'si, kaynak deposu veya
internet bağlantısı gerekmez.

## 7. Güvenlik ve doğruluk

- Secret doğrulamak için üçüncü taraf API'lere istek gönderilmez.
- Pattern ve entropy algılaması bağımsız olarak kapatılabilir.
- Pahalı regex'lere çalışma süresi sınırı uygulanır.
- Her yerleşik kalıbın pozitif ve negatif testleri bulunur.
- Entropy sonuçları `Low/Medium/High` güven seviyesiyle işaretlenir.
- Kullanıcı allowlist terimleri ve kalıpları ekleyebilir.
