# SMB/Kerberos teknik kararı

Durum: **Öneri — laboratuvar POC'u ile doğrulanacak**  
Tarih: **2026-08-13**

## Karar

Ana veri yolu için şu sürümleri sabitleyelim:

```text
Python                  3.12+
smbprotocol[kerberos]   1.17.0
pyspnego                0.12.1
```

Linux'ta Kerberos extra'sı `python-gssapi` ve `krb5` bağlarını kullanır; Kali,
Ubuntu ve Debian tabanında ayrıca `gcc`, `python3-dev` ve `libkrb5-dev` gerekir.
`smbprotocol` 1.17.0, Python 3.12'yi destekler ve SMB 2.0.2–3.1.1, signing,
encryption, dosya/dizin açma ve okuma işlemlerini yerleşik olarak sağlar.

Uygulama, global connection pool kullanan yüksek seviyeli `smbclient` arayüzüne
doğrudan bağlanmamalı. Küçük bir Nordis adapter'ı şu düşük seviyeli nesneleri
kullanmalı:

```text
Connection -> Session -> TreeConnect -> Open
```

Bunun nedeni; aynı TCP hedefi IP iken Kerberos SPN hostname'ini ayrı vermek,
kimlik doğrulama denemelerini görünür kılmak, ham NTSTATUS değerlerini korumak
ve byte-offset okumalarını doğrudan kontrol etmektir.

Kaynaklar: [smbprotocol 1.17.0](https://pypi.org/project/smbprotocol/),
[smbprotocol kaynak kodu](https://github.com/jborean93/smbprotocol/tree/v1.17.0),
[pyspnego 0.12.1](https://pypi.org/project/pyspnego/),
[pyspnego credential türleri](https://github.com/jborean93/pyspnego/blob/v0.12.1/src/spnego/_credential.py).

## Kimlik doğrulama modeli

`Auto` modu tek bir görünmez SPNEGO fallback'i kullanmayacak. Önce yalnız
Kerberos oturumu denenecek; uygun bir altyapı/protokol hatası oluşursa ve
kullanıcı fallback'e izin verdiyse bağlantı kapatılıp yeni bağlantıda yalnız
NTLM denenecek. Böylece iki denemenin sonucu ve kullanılan son yöntem kesin
olarak gösterilebilir.

| Girdi | Kerberos denemesi | NTLM denemesi |
|---|---|---|
| Kullanıcı + parola | `spnego.Password`, `auth_protocol="kerberos"` | Fallback açıksa aynı credential ile `auth_protocol="ntlm"` |
| NT hash / `LM:NT` | Uygulanmaz | `spnego.NTLMHash` ile pass-the-hash |
| CCache | `spnego.KerberosCCache("FILE:...")` | Tek başına mümkün değil |

Önemli sonuç: ham NT hash bu yığında **NTLM pass-the-hash** credential'ıdır;
pyspnego'nun `NTLMHash` türü Kerberos'u desteklemez. Kapsam belgesindeki “NT
hash ile KDC RC4 Kerberos denemesi” cümlesi bu kararla uyumlu değildir. Bu özel
ve modern domainlerde çoğu zaman kapalı olan yolu desteklemek zorunluysa ayrıca
başka bir Kerberos uygulaması gerekir; öneri, o cümleyi kaldırıp NT hash'i NTLM
ile sınırlamaktır.

Fallback yalnız DNS/SPN/KDC erişimi, clock-skew veya desteklenmeyen mekanizma
gibi Kerberos önkoşul hatalarında yapılmalı. Hatalı credential, kilitli/devre
dışı hesap, süresi dolmuş parola gibi hesap hatalarında ikinci bir logon
denemesi yapılmamalı. Bu hem sonucu daha doğru tutar hem gereksiz başarısız
logon olayını önler.

IP hedeflerinde soket IP'ye açılır; doğrulanmış FQDN, `Session` içindeki
`hostname_override` ile `cifs/<fqdn>` SPN'i için kullanılır. FQDN bulunamazsa
Kerberos sonucu açıkça `KERBEROS_HOSTNAME_UNRESOLVED` olur; sessizce IP-SPN
denenmez.

CCache web upload'ı özel bir POC maddesidir. pyspnego açık bir cache adı/path'i
ister. Linux'ta upload baytlarını diske yazmadan `memfd_create` ile RAM-backed
bir fd'ye koyup `FILE:/proc/self/fd/<n>` olarak verme yöntemi denenmeli ve fd
auth tamamlanana kadar açık tutulmalıdır. MIT/Heimdal uyumluluğu doğrulanmazsa
fail-closed davranılmalı; gizli bir temp dosya fallback'i yapılmamalıdır.

Pyspnego, bir credential listesiyle CCache'ten Kerberos ve NT hash'ten NTLM
fallback yapabilse de Nordis görünür deneme geçmişi istediği için ayrı oturum
denemeleri tercih edilmiştir. İlgili resmi örnek
[auth kaynak kodunda](https://github.com/jborean93/pyspnego/blob/v0.12.1/src/spnego/auth.py#L120-L137)
bulunur.

## Share ve dosya işlemleri

Share enumeration, `IPC$\\srvsvc` üzerinden [MS-SRVS `NetrShareEnum`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52)
ile aynı authenticated session üzerinde uygulanmalı. `smbprotocol` bunu hazır
bir yüksek seviye fonksiyon olarak sunmadığı için bu, yığının en önemli ek
adapter işidir. Resume handle/pagination desteklenmeli.

RPC erişimi reddedilir veya NAS bu metodu sunmazsa sonuç
`SHARE_ENUM_DENIED/UNAVAILABLE` olarak korunur ve repo içindeki bilinen share
listesi doğrudan `TreeConnect` ile denenir. Böylece enumeration başarısızlığı
“share yok” olarak yorumlanmaz.

Dosya ağacı için:

- `QueryDirectory`/create cevabından ad, tür, boyut, attribute ve zamanlar alınır.
- Dizin ve dosya handle'ları yalnız okuma/read-attributes haklarıyla açılır.
- `Open.read(offset, length)` ile parça veya istenen range okunur; yerel kopya
  ya da temp dosya oluşturulmaz.
- Extractor'lar için `io.RawIOBase` uyumlu `read/seek/tell/readinto` adapter'ı
  yazılır; seek yeni bir SMB range-read'e dönüşür.
- Parça boyutu, yapılandırma ile sunucunun negotiated `max_read_size` değerinin
  küçüğü olur.

`Open.read` offset ve length'i doğrudan kabul eder; kaynak:
[smbprotocol Open.read](https://github.com/jborean93/smbprotocol/blob/v1.17.0/src/smbprotocol/open.py#L1218-L1241).

## Dialect, signing ve encryption raporu

Adapter aşağıdaki public state'i normalize eder:

| Panel alanı | Kaynak |
|---|---|
| Dialect | `Connection.dialect` |
| Signing destekli/zorunlu | `Connection.server_security_mode` bitleri |
| Signing mevcut oturumda aktif | `Session.signing_required`; encryption aktifse `COVERED_BY_ENCRYPTION` |
| Encryption destekli | `Connection.supports_encryption` |
| Encryption oturumda aktif | `Session.encrypt_data` |
| Encryption share tarafından zorunlu | `TreeConnect.encrypt_data` |
| Share için etkin koruma | `Session.encrypt_data or TreeConnect.encrypt_data` |
| Seçilen algoritmalar | SMB 3.1.1'de `signing_algorithm_id` ve `cipher_id` |

SMB 3.0/3.0.2'de algoritma dialect'ten çıkarılıyorsa alan “negotiated” değil
“dialect gereği çıkarıldı” olarak etiketlenmeli. `SUPPORTED`, `REQUIRED` ve
`ACTIVE` birbirine karıştırılmamalıdır. Microsoft da bu değerleri ayrı bağlantı
state'i olarak tanımlar: [MS-SMB2 per-server state](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f388d7e0-9bc3-4d9c-98e5-71f8e36b3c4f).

Varsayılan bağlantı politikası:

```text
require_signing=True
require_encryption=False
require_secure_negotiate=True
```

`Session` düşük seviye API'sinde encryption varsayılanı `True` olduğundan ikinci
satır mutlaka açıkça verilmelidir; aksi halde SMB 2.x hedefleri gereksiz yere
başarısız olur. Sunucu veya share encryption zorunlu tutarsa kütüphane yine
encryption'ı etkinleştirir. SMB 3 encryption'ın daha sıkı veri koruması sağladığı
[MS-SMB2 güvenlik notunda](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/14b32996-29ca-4d5a-b888-a159af29e705)
belirtilir.

## Hata sadakati ve çalışma modeli

Tek bir `AUTH_FAILED` exception'ı üretmek yerine her hata şu alanlarla RAM'deki
event modeline çevrilmeli:

```text
stage, operation, target, raw_code, symbolic_name, safe_message, retryable
```

- TCP katmanında `socket`/`OSError.errno` korunur: timeout, refused, network veya
  host unreachable ayrı kalır.
- SMB katmanında `SMBResponseException.status` ham NTSTATUS olarak korunur;
  kütüphane `ACCESS_DENIED`, `LOGON_FAILURE`, `SHARING_VIOLATION` gibi typed
  exception'lar da sağlar.
- Kerberos katmanında `SpnegoError` ile native GSSAPI/Kerberos cause zinciri
  korunur; hata sınıflandırması string eşleştirmesine dayandırılmaz.

Kaynak: [smbprotocol exception modeli](https://github.com/jborean93/smbprotocol/blob/v1.17.0/src/smbprotocol/exceptions.py#L175-L244).

API blocking olduğundan hedef paralelliği bounded thread pool ile yapılmalı.
Bir hedefte tek `Connection/Session`, share ve dosya handle'ları kontrollü
şekilde kullanılmalı; iptal sırasında açık handle, tree, session ve socket'ler
sırayla kapatılmalıdır. Debug packet logging açılmamalı; resmi README debug
çıktısının SMB paketlerini ayrıntılı yazdığını belirtir. Uygulama file handler
kurmamalı.

## Neden Impacket ana yığın değil?

Impacket 0.13.1 de Python 3.12, parola/hash/ccache, yerleşik `listShares()` ve
offset'li `readFile()` sunar; özellikle share RPC tarafı daha hazırdır. Ancak
Nordis'in ana işi uzun süreli SMB veri okuma ile signing/encryption durumunu
ayrı ve doğru raporlamaktır. `smbprotocol` bu modern SMB state'ini, AES-CCM/GCM
şifrelemeyi ve typed NTSTATUS modelini daha doğrudan public API olarak sunar.
İki ayrı SMB client ile aynı hedefe iki kez login olan hibrit tasarım da
gereksiz karmaşıklık yaratır. Bu nedenle Impacket runtime bağımlılığı değil,
yalnız POC karşılaştırma aracı olabilir.

## Bilinen riskler

1. `smbprotocol` içinde hazır `listShares()` yoktur; SRVSVC adapter'ı Windows ve
   Samba/NAS hedeflerinde test edilmelidir.
2. `Session.username` tipi dokümantasyonda string görünse de değer doğrudan
   pyspnego'ya aktarılır; `KerberosCCache`/`NTLMHash` nesnesiyle bu entegrasyon
   sürüm pinleri ve integration test ile korunmalıdır.
3. CCache upload'ının `memfd` köprüsü MIT ve Heimdal Kerberos ile doğrulanmalıdır.
4. Kerberos DNS, doğru FQDN/SPN, KDC erişimi ve saat uyumuna bağlıdır.
5. `smbclient` DFS desteğini “experimental” olarak tanımlar; referral yalnız
   yetkili hedef kapsamındaysa takip edilmeli ve ayrıca test edilmelidir.
6. Yığın SMB1'i taramaz. TCP/445 açık fakat yalnız SMB1 sunan hedef ayrı bir
   read-only negotiate probe ile `SMB1_ONLY_UNSUPPORTED` olarak gösterilebilir.

## Küçük POC planı ve kabul ölçütleri

1. Windows Server domain member/DC ve Samba hedefinde parola, NT hash ve CCache
   ile FQDN/IP testleri yap; kullanılan yöntem ve ham hata kodunu doğrula.
2. Kerberos için başarılı akış, bozuk DNS, erişilemeyen KDC, bilinmeyen SPN,
   clock-skew ve hatalı parola senaryolarını çalıştır; yalnız izin verilen
   durumların görünür NTLM fallback yaptığını doğrula.
3. SRVSVC enumeration, pagination, enumeration-denied ve bilinen-share fallback
   senaryolarını test et.
4. Okunabilir, file-read-denied, directory-list-denied ve sharing-violation
   örneklerinde envanter durumlarını ve ham NTSTATUS'u doğrula.
5. Büyük bir dosyada baş/orta/son range-read ve ardışık chunk taraması yap;
   RSS'nin dosya boyutuyla büyümediğini ve çalışma dizini ile temp dizininde yeni
   dosya oluşmadığını doğrula.
6. SMB 2.1, 3.0.2 ve 3.1.1 hedeflerinde panel metadata'sını sunucu ayarıyla
   karşılaştır; signed/encrypted trafiğin raporlanan `ACTIVE` durumuyla uyuşması
   zorunlu olsun.

Bu altı madde geçmeden SMB adapter'ı diğer tarama katmanlarına bağlanmamalıdır.
