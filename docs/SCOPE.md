# Nordis SMB Inspector — Kapsam Taslağı

Durum: **v1.0 — 2026-08-13 tarihinde kapsam kararı olarak kilitlendi**

## 1. Amaç

Yetkilendirilmiş bir ağ kapsamındaki SMB servislerini bulmak, kullanıcının
sağladığı hesapla okunabilen paylaşımları ve dosyaları envanterlemek, desteklenen
dosyaların içeriğinde seçilen kelime listesini aramak ve eşleşen içeriği
anlaşılır bir web arayüzünde canlı göstermek.

Bu belge eksik özellikli bir "MVP" tanımlamaz; hedeflenen ilk ürün sürümünün
kapsamını tanımlar. Uygulama test edilebilir aşamalar halinde geliştirilecektir.

## 2. Temel kullanıcı akışı

1. Kullanıcı tek alana virgülle ayrılmış IP ve CIDR değerlerini karışık olarak
   girer. Örnek: `10.10.10.4, 10.10.20.0/24, 10.10.30.7`.
2. Domain, kullanıcı adı ve parola güvenli bir form üzerinden sağlanır; kimlik
   doğrulama modu seçilir.
3. Repo ile gelen bir wordlist seçilir, harici `.txt` wordlist yüklenir veya
   taramaya tek tek ek arama terimleri eklenir.
4. Araç yalnızca kapsam içindeki sistemlerde SMB erişimini kontrol eder.
5. Hesabın erişebildiği paylaşımlar, klasörler ve dosyalar listelenir.
6. Desteklenen dosya içerikleri okunur ve seçilen terimler aranır.
7. Her IP'nin TCP, SMB, kimlik doğrulama ve paylaşım erişimi sonucu ayrı
   gösterilir.
8. İçerik eşleşmeleri maskelenmeden, tam eşleşen satır veya belge konumuyla
   tarama oturumu sırasında canlı gösterilir.

## 3. İlk sürüm işlevleri

### 3.1 Tarama tanımı

- Tek metin alanında virgülle ayrılmış IP, CIDR ve hostname değerlerini karışık kullanma
- Boşlukları temizleme, CIDR'ları IP'lere genişletme ve tekrarları tekilleştirme
- Hatalı girdiyi tarama başlamadan, ilgili değerle birlikte gösterme
- CIDR adreslerini yalnız tarama kuyruğu tüketirken tembel olarak genişletme;
  olası adres sayısını cihaz veya erişilebilir hedef sayısı olarak göstermeme
- Hostname birden fazla IP'ye çözülürse bütün adresleri kaynak hostname ile gösterme
- Domain/kullanıcı adıyla birlikte parola, NT hash veya Kerberos ccache girdisi
- `Auto (Kerberos öncelikli)`, `Yalnız Kerberos` ve `Yalnız NTLM` modları
- Kerberos için hedef IP'yi FQDN'e çözme ve `cifs/<hostname>` SPN'ini kullanma
- Her hedefte gerçekten kullanılan kimlik doğrulama yöntemini gösterme
- Port, zaman aşımı, eşzamanlılık ve çıkarıcıya özgü kaynak sınırı ayarları
- Kullanıcı tarafından ayarlanabilen maksimum klasör derinliği
- Kapsamın kullanıcı tarafından onaylandığına dair zorunlu onay kutusu
- Tarama başlatma, iptal etme ve durum görüntüleme
- Taranacak kaynak ifadesi için tek açık onay; gizli hedef sınırı uygulanmaz

Credential girdileri:

| Tür | Kullanım |
|---|---|
| Parola | Kerberos kimlik doğrulaması; izin verilmişse NTLM fallback |
| NT hash | Yalnız NTLM pass-the-hash; Kerberos anahtarı olarak yorumlanmaz |
| CCache | Cache içindeki TGT veya uygun `cifs/<hostname>` service ticket ile Kerberos |

- NT hash alanı 32 hexadecimal karakteri doğrular; uyumluluk için `LMHASH:NTHASH`
  biçimi alınırsa yalnız NT hash bölümü kullanılır.
- CCache tarayıcıdan dosya olarak seçilir ve kalıcı depolamaya yazılmadan işlenir.
- CCache içindeki principal/realm, geçerlilik süresi ve kullanılabilir ticket türü
  canlı arayüzde gösterilir; ticket içeriği loglanmaz.
- Parola, NT hash ve ccache birbirinden ayrı credential türleridir; kullanıcı
  aktif tarama için kullanılacak türü seçer.
- NT hash seçildiğinde auth modu `Yalnız NTLM` olur. `Auto` ve `Yalnız
  Kerberos` bu credential türü için sunulmaz; böylece desteklenmeyen bir
  Kerberos denemesi yapılıyor izlenimi oluşmaz.
- Yalnız ccache sağlanmışsa NTLM fallback yapılamaz; bu durum
  `NTLM_FALLBACK_UNAVAILABLE` olarak gösterilir.

`Auto` modunda Kerberos denemesi ve varsa NTLM fallback sonucu ayrı ayrı görünür
olmalıdır; araç hangi yöntemin kullanıldığını gizlememelidir.

Kerberos tanılama görünümü, tek bir `AUTH_FAILED` yerine en az şu sonuçları
ayırt eder: DNS/FQDN çözümlenemedi, KDC bulunamadı veya erişilemedi, realm/domain
uyuşmazlığı, saat farkı, kullanıcı ön kimlik doğrulaması başarısız, hesap durumu
hatası, `cifs/<hostname>` SPN'i bulunamadı, ticket süresi doldu ve NTLM fallback
kullanıldı. Alınabiliyorsa özgün Kerberos hata kodu da canlı ekranda gösterilir.

### 3.2 Liste yönetimi

İki farklı liste türü birbirinden ayrı yönetilir:

1. **İçerik arama listesi:** Dosyaların içinde aranacak kelime ve ifadeler.
2. **Bilinen share adları listesi:** Share listeleme engellendiğinde veya kullanıcı
   özellikle istediğinde doğrudan bağlanılması denenecek share adları.

İçerik arama listesi:

- Uygulamayla gelen varsayılan Türkçe/İngilizce hassas veri kelime listesi
- Repo içinde sürüm kontrollü olarak sağlanan varsayılan liste
- Bir tarama için bir veya daha fazla hazır liste seçebilme
- Satır başına bir terim içeren `.txt` dosyası yükleyebilme
- Tarama formundan harici kelime/ifade ekleyebilme
- Varsayılan olarak büyük/küçük harf duyarsız alt metin araması
- İsteğe bağlı case-sensitive, tam kelime ve regex arama modları
- Aynı terimleri tekilleştirme ve boş/geçersiz satırları reddetme
- Kullanılacak birleşik listenin taramadan önce önizlenmesi
- Kategori bazlı kural paketlerini açma/kapatma
- Wordlist aramasından bağımsız regex/token, private-key, yapılandırma-ataması
  ve entropy algılayıcılarını açma/kapatma

Bilinen share adları listesi:

- Repo içinde sürüm kontrollü olarak sağlanan düzenlenebilir başlangıç listesi
- Satır başına bir share adı içeren `.txt` dosyası yükleme
- Web panelinden ad ekleme, çıkarma ve düzenleme
- Listeyi yalnız share enumeration başarısız olduğunda veya her hedefte kullanma seçeneği
- Denenen her ad için `NOT_FOUND`, `ACCESS_DENIED` veya `CONNECTED` sonucunu gösterme

Hazır listeler proje yapılandırmasıdır; tarama sonucu değildir. Varsayılan
içerik ve share listeleri repo içinde tutulur. Web panelinde kaydedilen
düzenlemeler bu yapılandırma dosyalarına yazılır. Credential, hedef, envanter ve
bulgu verileri bu mekanizmaya hiçbir zaman yazılmaz.

İçerik wordlist'leri kategori bazında normal `.txt` dosyalarıdır; web panelinde
ayrı ayrı seçilir ve düzenlenir. Kalıp algılama bunları üretmez veya değiştirmez;
wordlist'ten bağımsız ikinci bir tarama yöntemidir. Ayrıntılı tasarım
[DETECTION.md](DETECTION.md) belgesindedir.

Regex modunda hatalı veya pahalı ifadelerin taramayı kilitlememesi için süre ve
karmaşıklık sınırı uygulanır.

### 3.3 Hedef bağlantı durumları

Her genişletilmiş IP için sonuca yalnızca "başarılı/başarısız" yazılmaz. Aşamalar
ve alınan düşük seviye sonuç ayrı tutulur:

| Aşama | Durum | Anlamı |
|---|---|---|
| Ağ/TCP | `TIMEOUT_NO_RESPONSE` | Süre içinde TCP yanıtı yok; host kapalı veya filtreli olabilir, kesin neden varsayılmaz |
| Ağ/TCP | `NETWORK_UNREACHABLE` | Yerel ağ yığını hedefe rota olmadığını bildirdi |
| Ağ/TCP | `CONNECTION_REFUSED` | Hedef TCP bağlantısını açıkça reddetti; genellikle 445 kapalı |
| Ağ/TCP | `PORT_OPEN` | TCP/445 bağlantısı kuruldu |
| SMB | `NEGOTIATION_FAILED` | Port açık fakat SMB protokol görüşmesi tamamlanamadı |
| Kimlik doğrulama | `AUTH_FAILED` | SMB çalışıyor fakat sağlanan hesap kabul edilmedi |
| Yetkilendirme | `ACCESS_DENIED` | Kimlik doğrulandı fakat paylaşım veya yol için okuma yetkisi yok |
| Tarama | `PARTIAL_ACCESS` | Bazı paylaşım/yollar okunabildi, bazıları reddedildi |
| Tarama | `COMPLETED` | Erişilebilen içeriklerin taraması tamamlandı |

Web panelindeki hedef tablosunda şu alanlar bulunur:

- Girilen kaynak değer (IP veya CIDR) ve genişletilmiş IP
- Girilen domain/realm, çözümlenen FQDN ve kullanılan KDC/DC
- TCP/445 sonucu ve bağlantı süresi
- SMB görüşme sonucu ve dialect/sürüm
- Kerberos/NTLM deneme ve kimlik doğrulama sonucu
- Görülen ve okunabilen paylaşım sayısı
- Son başarılı aşama
- İşletim sistemi hata kodu veya SMB status kodu ve sade açıklaması

### 3.4 SMB envanteri

- SMB erişimi bulunan hedefler
- Başarılı/başarısız kimlik doğrulama sonucu; hata nedeni güvenli biçimde
- Görülebilen paylaşımlar ve paylaşım türü
- Okunabilen klasör/dosya yolları, boyut ve değiştirilme zamanı
- Erişim reddedilen konumların içeriklerini zorlamadan kayda geçirilmesi
- Arama terimi eşleşmeyen dosyalar dahil görülebilen bütün dosyaları gösterme
- Her dosyada içerik tarama durumu ve eşleşme sayısı
- Ayarlanan maksimum derinliğe ulaşılan klasörleri `DEPTH_LIMIT_REACHED` olarak gösterme

Varsayılan davranış, erişilebilen bütün disk/file share'lerini maksimum derinliğe
kadar taramaktır. Arama terimi bulunmayan dosyalar da envanterde kalır. `IPC$`
ve yazıcı gibi dosya ağacı olmayan share türleri gösterilir ancak içerik taramasına
alınmaz.

İsteğe bağlı filtrelerin anlamı:

- **Dahil et:** Yalnız belirtilen share veya path'leri tara. Örnek: `Finance`,
  `Public/Projects`.
- **Hariç tut:** Diğer her şeyi tara fakat belirtilen share veya path'leri atla.
  Örnek: `C$/Windows`, `*/node_modules`.

Kullanıcı filtre girmezse hiçbir erişilebilir file share bu nedenle atlanmaz.

### 3.5 SMB bağlantı güvenliği bilgileri

SMB protokol görüşmesinden alınabilen bilgiler hedef bazında gösterilir:

- Müzakere edilen dialect: SMB 1.0, 2.0.2, 2.1, 3.0, 3.0.2 veya 3.1.1
- Signing desteği, signing zorunluluğu ve mevcut oturumda signing kullanımı
- Encryption desteği, sunucu/share tarafından zorunlu tutulup tutulmadığı ve
  mevcut oturumda encryption kullanımı
- Alınabiliyorsa seçilen signing/encryption algoritması

Bu bölüm yalnız görüşme ve kurulan oturum bilgisini raporlar; zafiyet sömürüsü
veya ayar değiştirme yapmaz.

Ana tarama veri yolu SMB 2.0.2–3.1.1 destekler. Yalnız SMB1 sunan hedef varsa
salt-okunur görüşme probu bunu `SMB1_ONLY_UNSUPPORTED` olarak gösterir; SMB1 ile
dosya ağacına bağlanılmaz.

### 3.6 İçerik arama

Planlanan biçimler:

- Düz metin, yapılandırma ve kaynak kodu: TXT, LOG, CSV, TSV, INI, CONF, CFG,
  ENV, PROPERTIES, YAML, JSON, JSONL, XML, TOML, MD, RST, SQL, REG, INF, PS1,
  BAT, CMD, SH ve yaygın programlama dili kaynak dosyaları
- Microsoft Office Open XML: DOCX, XLSX, PPTX
- OpenDocument: ODT, ODS, ODP
- PDF (metin katmanı bulunan dosyalar), RTF ve HTML
- E-posta: EML; MSG desteği uygun çıkarıcıyla
- Arşivler: ZIP, TAR ve GZIP; 7z desteği uygun çıkarıcıyla
- Eski Office biçimleri DOC, XLS ve PPT; güvenilir çıkarıcı mevcutsa

Metin kodlaması algılama sırası:

1. BOM üzerinden UTF-8/16/32
2. Geçerli UTF-8 kontrolü
3. Kodlama algılayıcıyla Windows-1254, Windows-1252, ISO-8859-9 ve diğer adaylar
4. Algılanamayan içerikte `ENCODING_UNDETERMINED` durumu

Algılanan kodlama ve güven skoru dosya envanterinde gösterilir. Arşivler için
ayrı iç içe geçme, toplam açılmış boyut ve dosya sayısı sınırları uygulanır.
İçerik çıkarıcılarının bellek akışıyla çalışması gerekir; geçici disk dosyası
zorunlu olan çıkarıcılar kullanılmaz.

Eşleşme kaydı:

- Hedef IP veya hostname
- Paylaşım ve dosyanın UNC yolu
- Eşleşen terim
- Algılama yöntemi: `WORDLIST`, `PATTERN` veya `ENTROPY`
- Kalıp bulgularında kural kimliği, kategori ve güven seviyesi
- Kerberos/NTLM/hash artifact bulgularında algılanan format ve varsa etype
- Aynı dosyadaki her eşleşme için ayrı kayıt ve dosya düzeyinde toplam eşleşme sayısı
- TXT benzeri dosyalarda satır numarası
- PDF'de sayfa; Office dosyalarında paragraf, slayt veya hücre konumu
- Düz metinlerde eşleşmenin bulunduğu tam satır
- PDF/Office dosyalarında eşleşmenin bulunduğu tam paragraf, hücre veya metin bloğu
- Dosya boyutu, değiştirilme zamanı ve tarama zamanı

Eşleşen satır/metin web panelinde maskelenmeden, canlı tarama oturumu içinde
gösterilir. Credential, envanter, durum ve eşleşme verisi loglanmaz veya kalıcı
depolamaya yazılmaz.

Bir klasör listelenebiliyor ancak içindeki bir dosya açılamıyorsa dosya yine
envantere eklenir ve `FILE_READ_DENIED` olarak gösterilir. Klasörün kendisi
listelenemiyorsa içerideki bilinmeyen dosyalar tahmin edilmez; yalnızca ilgili
klasör `DIRECTORY_LIST_DENIED` olarak gösterilir.

Dosya işleme durumları:

| Durum | Anlamı |
|---|---|
| `FILE_READABLE` | Dosya açıldı ve destekleniyorsa içeriği tarandı |
| `FILE_READ_DENIED` | Dosya listede görüldü ancak okuma izni reddedildi |
| `DIRECTORY_LIST_DENIED` | Klasör görüldü ancak içindeki dosyalar listelenemedi |
| `SHARING_VIOLATION` | Dosya başka bir işlem nedeniyle okumaya açılamadı |
| `UNSUPPORTED_TYPE` | Dosya mevcut fakat içerik çıkarıcısı bulunmuyor |
| `ENCRYPTED_OR_PROTECTED` | Dosya mevcut fakat parola/koruma nedeniyle okunamadı |
| `EXTRACTOR_LIMIT_REACHED` | Dosya mevcut; seçilen çıkarıcının açık kaynak sınırına ulaşıldı |
| `READ_ERROR` | Diğer okuma/protokol hatası; özgün status kodu ayrıca gösterilir |

İkili dosyalar, şifreli belgeler ve görüntü tabanlı PDF/OCR ilk sürümde içerik
aramasına dahil değildir; envanterde yine gösterilebilir.

### 3.7 Web arayüzü

- Yerel makinede çalışan, varsayılan olarak dış ağa açılmayan basit web paneli
- Yeni tarama formu
- Wordlist seçme/yükleme/düzenleme görünümü
- Canlı durum: hedef, paylaşım, dosya ve hata sayaçları
- Güncel tarama fazı, tahmini genel yüzde ve faza özel kesin sayaçlar
- Aynı anda çalışan işler için aktif hedef/share/dosya listesi
- Hedef bazında bağlantı aşamaları ve hata sınıfları tablosu
- Canlı hedef tablosunda yalnız TCP yanıtı alınarak varlığı doğrulanan IP'ler;
  yanıtsız/ulaşılamayan adresler satır olarak değil yalnız faz sayacı olarak tutulur
- Okunabilen ve okunamayan öğeleri nedenleriyle içeren dosya envanteri görünümü
- Maskesiz eşleşen satırı gösteren filtrelenebilir canlı bulgular tablosu
- Wordlist, pattern ve entropy bulgularını ayrı ayrı filtreleme

Canlı tarama fazları:

| Faz | Gösterilecek ilerleme |
|---|---|
| Hedefleri hazırlama | Girdi doğrulama, CIDR genişletme ve toplam IP sayısı |
| Bağlantı kontrolü | Kontrol edilen IP / toplam IP ve yüzde |
| SMB/Kimlik doğrulama | Görüşülen ve doğrulanan hedef / erişilebilir hedef |
| Share keşfi | İşlenen hedef ve bulunan/denenen share sayaçları |
| Dosya envanteri | Aktif hedef/share/path, klasör ve dosya sayaçları |
| İçerik tarama | Taranan dosya / envanterlenen uygun dosya, okunan byte ve yüzde |
| Tamamlandı | Başarılı, kısmi, reddedilen ve hatalı hedeflerin özeti |

Klasör ağacının toplam büyüklüğü keşif bitmeden bilinemez. Bu nedenle dosya
envanteri fazında kesin olmayan bir yüzde gerçekmiş gibi gösterilmez; faz,
aktif işler ve artan sayaçlar gösterilir. Envanter tamamlandıktan sonra içerik
tarama yüzdesi kesin hesaplanır. Genel yüzde bu ayrımı koruyarak "tahmini"
etiketi taşır.

Tarama iki ana geçişten oluşur:

1. Hedef, share, klasör ve dosya envanteri tamamen çıkarılır.
2. İçerik taramasına uygun dosyalar üzerinde kelime araması yapılır.

Bu sayede ikinci geçişte toplam iş miktarı bilinir ve kesin dosya/byte yüzdesi
gösterilebilir.

### 3.8 Tarama yükü ve hız kontrolü

Tarama hızı sonucu değiştiren bir filtre değildir; aynı kapsamın ağ ve dosya
sunucusu üzerinde ne kadar paralel çalışmayla taranacağını belirler:

- Aynı anda kontrol edilen hedef sayısı
- Hedef başına aynı anda işlenen share/dosya sayısı
- Aynı anda açık tutulabilecek SMB dosya handle sayısı
- Bağlantı ve dosya okuma zaman aşımı
- Geçici ağ hatalarında yeniden deneme sayısı
- İstenirse toplam okuma bant genişliği sınırı

Web panelinde hazır `Düşük yük`, `Dengeli` ve `Hızlı` profilleri ile ayrıntılı
özel ayar bulunur. Yüksek değerler daha hızlı sonuç verebilir ancak sunucu CPU,
disk, ağ ve SMB bağlantı limitlerini daha fazla kullanır. Düşük değerler daha
uzun sürer fakat üretim ortamına daha az yük bindirir. Hangi profil seçilirse
seçilsin, dosya atlanmaz; yalnız çalışma paralelliği değişir.

### 3.9 Kesinleşen varsayılanlar

- Uygulama tek kullanıcı için yerel çalışır, yalnız `127.0.0.1` üzerinde dinler
  ve giriş ekranı içermez.
- Hedef alanı IP, CIDR ve hostname kabul eder.
- Varsayılan auth modu `Auto`dur: Kerberos önce denenir, başarısız olursa NTLM
  fallback uygulanır ve bu geçiş hedef satırında açıkça gösterilir.
- Wordlist araması varsayılan olarak case-insensitive alt metin modundadır.
- Pattern taraması varsayılan açıktır; genel entropy taraması varsayılan kapalıdır.
- Varsayılan içerik wordlist kategorileri: genel credential terimleri, Türkçe,
  Windows/AD, veritabanı, cloud/API/SaaS, DevOps/otomasyon ve network/VPN.

## 4. Güvenlik ve veri koruma sınırları

- Yalnızca kullanıcı tarafından girilen kapsam taranır; kapsam dışına yönelme yoktur.
- Brute-force, password spraying, hesap keşfi ve yetki yükseltme yapılmaz.
- SMB üzerinde dosya oluşturma, değiştirme veya silme işlemi yapılmaz.
- Credential komut satırı argümanı veya URL içinde taşınmaz.
- Credential ve tarama sonuçları kalıcı depolamaya yazılmaz.
- Bulunan eşleşme satırları canlı web görünümünde maskelenmeden gösterilir.
- Credential, hedef durumu, dosya yolu ve eşleşme içeriği loglanmaz.
- Dosya içerikleri geçici dosya oluşturulmadan, sabit boyutlu parçalar ve
  sınırlandırılmış bellek tamponları üzerinden işlenir. Düz metinler için genel
  bir dosya boyutu kesmesi uygulanmaz.
- Web yanıtlarında `Cache-Control: no-store` kullanılır; tarama verileri
  `localStorage`, `sessionStorage`, IndexedDB veya service worker'a yazılmaz.
- Web sunucusunun erişim logları kapatılır.
- Tek satır/tampon boyutu, çıkarıcı kaynak kullanımı, derinlik, süre ve
  eşzamanlılık limitleri zorunludur; bu limitler dosyayı envanterden çıkarmaz.
- Tanılama ve hata ayrıntıları yalnızca canlı web oturumunda gösterilir.

## 5. Kapsam dışı

- Credential brute-force veya spraying
- SMB zafiyet sömürüsü
- Paylaşım izinlerini değiştirme
- Dosya indirme/kopyalama arayüzü
- Dosyaya yazma, silme veya karantinaya alma
- Hash çıkarma veya kimlik bilgisi ele geçirme
- OCR ve parola korumalı içeriklerin şifresini kırma
- İnternet üzerinden çok kullanıcılı/SaaS dağıtımı

## 6. Teknik yaklaşım

- Python 3.12+
- SMB veri yolu için sabitlenmiş `smbprotocol[kerberos]` + `pyspnego`; düşük
  seviyeli `Connection -> Session -> TreeConnect -> Open` adaptörü. Ayrıntılar
  ve laboratuvar geçitleri [TECH_SMB.md](TECH_SMB.md) belgesindedir.
- Yerel panel için Starlette + Uvicorn + Jinja2 + vanilla JavaScript; canlı
  akış için SSE kullanılacak. Karar ve kabul kontrolleri
  [TECH_WEB.md](TECH_WEB.md) belgesindedir.
- İlk olarak SMB/Kerberos kitaplıkları küçük bir teknik deneyle karşılaştırılacak
- Lisansı uygun başlangıç secret rule corpus'u Nordis kategori/modeline dahil
  edilir ve harici runtime bağımlılığı olmadan Nordis motorunda çalıştırılır
- Genel secret, Windows/AD ve hash artifact kuralları tek **Nordis Detection
  Rules** seti olarak proje sırasında hazırlanır ve ilk sürümle sabitlenir
- Uygulamada rule set güncelleme veya upstream senkronizasyon özelliği bulunmaz
- Web arayüzü sunucu tarafında üretilebilir; ayrı bir frontend zorunlu değildir
- Arka plan taraması iptal edilebilir kontrollü bir iş yürütücüsünde çalışır
- Credential, bulgu, envanter veya tarama metadata'sı için kalıcı veri katmanı yoktur
- Dosya çıkarıcıları ayrı adaptörler halinde

Katmanlar:

```text
Web UI / API
      |
Scan Orchestrator
  |       |       |
Scope   SMB     Wordlist
Guard   Client   Matcher
          |
     File Extractors
          |
Live Findings / Inventory
```

## 7. Örnek bulgu

```text
Hedef:       10.20.30.15
Paylaşım:    Finance
Dosya:       Archive/application.ini
UNC:         \\10.20.30.15\Finance\Archive\application.ini
Terim:       password
Konum:       Satır 18
Eşleşen satır: database_password = PlainTextValue!
Tespit:      2026-08-13T17:30:00+03:00
```

## 8. Kodlama sırasında doğrulanacak teknik kararlar

- SMB/Kerberos kitaplığı; parola, NT hash, ccache, signing ve encryption
  gereksinimleri için küçük entegrasyon deneyiyle seçilecek.
- Yerel web çatısı; canlı ilerleme aktarımı, iptal ve paketleme deneyiyle seçilecek.
- Geniş dosya biçimleri için yalnız bellek akışıyla güvenilir çalışan çıkarıcılar
  etkinleştirilecek; desteklenmeyen biçimler envanterde açıkça işaretlenecek.
- Başlangıç wordlist terimleri ve sabit pattern corpus'u pozitif/negatif test
  örnekleriyle küratörlü olarak hazırlanacak.
- Klasör derinliği için döngü/reparse-point davranışı test edilecek; sabit `32`
  gibi doğrulanmamış bir sayı varsayılan kabul edilmeyecek.
- Düz metin dosyaları mümkün olduğunda stream edilerek boyutundan bağımsız
  taranacak. PDF/Office/arşiv gibi seek veya toplu bellek gerektiren biçimlerin
  sınırları extractor ve bellek testleri sonucunda belirlenecek.
- Arşiv güvenlik sınırları; iç içe geçme, açılmış toplam byte, üye sayısı ve
  sıkıştırma oranı testleriyle belirlenecek ve panelden değiştirilebilir olacak.

## 9. İlk sürüm kabul ölçütleri

- Yetkili bir test subnetinde SMB açık hedefleri kapsam dışına çıkmadan bulur.
- Verilen tek hesabı kullanarak okunabilen paylaşım ve dosyaları listeler.
- Her IP için timeout, connection refused, SMB/auth hatası ve access denied
  sonuçlarını birbirinden ayırır.
- Kerberos'u FQDN/SPN mevcut olduğunda kullanır ve kullanılan auth yöntemini gösterir.
- Parola, NT hash ve ccache girdilerini birbirine karıştırmadan doğrular ve
  kullanılan credential/auth türünü canlı gösterir.
- Listelenebilen ancak okunamayan dosyaları ve listelenemeyen klasörleri ilgili
  hata nedeniyle birlikte gösterir.
- Eşleşme bulunmayanlar dahil bütün görülebilen dosyaları envanterde gösterir.
- Varsayılan, yüklenen ve elle eklenen terimleri tek taramada birleştirir.
- Desteklenen örnek dosyalarda bütün eşleşmeleri tam satır ve doğru konumla canlı gösterir.
- CIDR'dan açılan IP'leri, güncel fazı, aktif işleri ve mümkün olan fazlarda kesin
  ilerleme yüzdesini canlı gösterir.
- Giriş credential'ını ve eşleşen hassas satırları loglara yazmaz.
- Taramayı iptal edebilir; credential, sonuç veya hassas satırları kalıcı depolamaya yazmaz.
