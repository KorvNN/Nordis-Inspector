# Nordis SMB Inspector — Yerel Web Teknolojisi Kararı

Değerlendirme tarihi: **2026-08-13**  
Hedef Python sürümü: **3.12+**

## Karar

Yerel panel için **Starlette + Uvicorn + Jinja2 + yerel vanilla JavaScript**
kullanılacak. FastAPI kullanılmayacak.

- Starlette, ihtiyacımız olan ASGI yaşam döngüsü, streaming response, uygulama
  state'i, middleware ve Jinja entegrasyonunu doğrudan sağlar; kendisini de az
  bağımlılıklı ve düşük karmaşıklıklı bir ASGI toolkit'i olarak tanımlar
  ([Starlette özellikleri](https://www.starlette.io/),
  [templates](https://www.starlette.io/templates/),
  [lifespan](https://www.starlette.io/lifespan/)).
- Uvicorn varsayılan olarak `127.0.0.1` üzerinde dinler ve erişim logunu ayrı
  olarak kapatma seçeneği sunar. Uygulama yine de bu değerleri varsaymak yerine
  launcher içinde açıkça sabitleyecek
  ([Uvicorn ayarları](https://www.uvicorn.org/settings/)).
- Arayüz bir SPA olmayacak: ilk sayfa Jinja ile sunucuda üretilecek; küçük,
  paketle birlikte gelen JavaScript yalnız canlı tabloları ve sayaçları
  güncelleyecek. React/Vue, Node build zinciri, CDN ve harici web asset'i yok.

Canlı güncelleme için **SSE** kullanılacak. Starlette'in yerleşik
`StreamingResponse` sınıfı async generator akışını destekliyor
([responses](https://www.starlette.io/responses/)); SSE çerçevelerini küçük bir
uygulama adaptörü üretecek. Ayrı bir SSE paketi veya WebSocket gerekmiyor. Akış
sunucudan tarayıcıya tek yönlüdür; iptal ayrı bir `POST` isteğidir.

## Seçeneklerin karşılaştırması

| Seçenek | Güçlü tarafı | Bu proje için sorun / gereksiz kısım | Sonuç |
|---|---|---|---|
| **Starlette** | Async-first; streaming, lifespan/state, middleware, Jinja ve test client mevcut | SSE framing ve basit form doğrulaması bizde olur | **Seçildi** |
| **FastAPI** | Starlette'in üstüne Pydantic doğrulaması, dependency injection ve OpenAPI ekler | Panel tek süreçli ve küçük bir iç API'ye sahip; ek API katmanının getirisi yok. FastAPI'nin kendisi Starlette alt sınıfıdır ([resmî özellikler](https://fastapi.tiangolo.com/features/)) | Şimdilik kullanma |
| **Flask** | Jinja ve klasik server-rendered form akışı çok rahattır | WSGI modelinde async view başına bir worker tutulur; view sonlanınca oluşturulan async background task'lar iptal edilir. Uzun yaşayan, canlı ve iptal edilebilir tarama için ek thread/queue veya ASGI adaptörü gerekir ([Flask async notları](https://flask.palletsprojects.com/en/stable/async-await/)) | Kullanma |
| **aiohttp** | Async-first; streaming/WebSocket ve uygulama yaşam döngüsü güçlü, access log `None` ile kapatılabilir ([server](https://docs.aiohttp.org/en/stable/web_reference.html), [logging](https://docs.aiohttp.org/en/stable/logging.html)) | Template rendering çekirdekte yok; Jinja ayrı entegrasyondur ([aiohttp eklentileri](https://docs.aiohttp.org/en/stable/third_party.html)). Starlette aynı ihtiyacı daha az yapıştırma koduyla karşılıyor | İyi ikinci seçenek |

## Çalışma modeli

Tek process ve tek Uvicorn worker çalışır. Bunun nedeni performans değil,
credential, envanter ve bulguların tek bir RAM içi oturumda tutulmasıdır.

```text
Jinja sayfası + vanilla JS
        |  POST /scan, POST /scan/cancel
        |  GET /scan/events (SSE)
        |  GET /scan/snapshot ve sayfalı tablolar
        v
Starlette route'ları
        v
RAM içi ScanSession + event broker
        v
İptal edilebilir Scan Orchestrator
```

Starlette `lifespan` içinde uzun ömürlü bir AnyIO task group açılır. Her tarama
kendi cancel scope'u içinde çalışır; iptal endpoint'i yalnız o scope'u iptal
eder. Task group'ların kendi cancel scope'u olduğu AnyIO'nun resmî
dokümantasyonunda belirtilir
([AnyIO cancellation](https://anyio.readthedocs.io/en/stable/cancellation.html)).
Starlette de lifespan görevleri için task group kullanılmasını önerir
([Starlette lifespan](https://www.starlette.io/lifespan/)).

Starlette/FastAPI `BackgroundTask(s)` mekanizması tarama yürütücüsü olarak
kullanılmayacak. Taramanın kimliği, durumu ve açık iptal kolu response'dan
bağımsız olarak uygulama yaşam döngüsünde yönetilecek.

### Önerilen endpoint sınırı

| Yöntem ve yol | Amaç |
|---|---|
| `GET /` | Server-rendered başlangıç paneli |
| `POST /scan` | Tek aktif taramayı başlat; credential ve ayarlar yalnız request body'de |
| `GET /scan/snapshot` | Yenileme/yeniden bağlanma için mevcut RAM durumunu getir |
| `GET /scan/events` | SSE ile faz, sayaç ve değişiklik olaylarını aktar |
| `POST /scan/cancel` | Kooperatif iptal isteği ver |
| `GET /inventory` | RAM envanterini filtreli ve sayfalı getir |
| `GET /findings` | RAM bulgularını filtreli ve sayfalı getir |

Credential, NT hash, hedef, arama terimi veya dosya yolu URL/query string'e
konulmayacak.

### Olay modeli

En az şu olaylar bulunur:

- `snapshot`
- `phase.changed`
- `counters.changed`
- `target.changed`
- `share.changed`
- `file.changed`
- `finding.added`
- `scan.completed`, `scan.cancelled`, `scan.failed`

Sayaç ve dosya olayları küçük partiler halinde ve en fazla yaklaşık 5–10 ekran
güncellemesi/saniye hızında birleştirilir. Bu tarama hızını sınırlamaz; yalnız
DOM ve SSE gürültüsünü azaltır. Event kuyruğu bounded olur; istemci geri kalırsa
eski ara olayları biriktirmek yerine yeni bir `snapshot` ister. Büyük envanterin
tamamı DOM'a basılmaz; tablolar RAM'deki kaynak üzerinden sayfalı/filtreli
gösterilir.

SSE bağlantısının kopması taramayı iptal etmez. Sayfa yeniden açıldığında önce
snapshot alınır, sonra canlı akışa yeniden bağlanılır. İptal yalnız kullanıcının
iptal düğmesi, uygulama kapanışı veya fatal scan hatasıyla gerçekleşir.

## Veri koruma ve yerel sunucu ayarları

- Host değeri kullanıcıya açılan bir seçenek olmaz: tam olarak `127.0.0.1`.
- Tek worker, `reload=false`, `debug=false`, `access_log=false`; release
  çalıştırmasında traceback web sayfası yoktur. Uvicorn erişim logunu kapatmayı
  resmen destekler ([ayarlar](https://www.uvicorn.org/settings/)).
- Bütün HTTP yanıtlarına saf ASGI middleware ile en az
  `Cache-Control: no-store, max-age=0` uygulanır. Starlette response header'larını
  middleware'de değiştirme modelini belgeler
  ([middleware](https://www.starlette.io/middleware/)).
- Cookie/session kullanılmaz. JavaScript `localStorage`, `sessionStorage`,
  IndexedDB, Cache API veya service worker kullanmaz. Bütün JS/CSS/font dosyaları
  wheel içinde gelir; ağdan asset çekilmez.
- `TrustedHostMiddleware` yalnız `127.0.0.1` host'una izin verir. State değiştiren
  POST'lar aynı-origin kontrolü ve uygulama başlarken RAM'de üretilen, sayfanın
  DOM'unda tutulan bir CSRF nonce'u ister. Bu kullanıcı girişi değildir
  ([TrustedHostMiddleware](https://www.starlette.io/middleware/#trustedhostmiddleware)).
- CORS açılmaz. Önerilen ek header'lar:
  `Content-Security-Policy: default-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'`,
  `Referrer-Policy: no-referrer` ve `X-Content-Type-Options: nosniff`.
- Uygulama logları request body, credential, hedef, UNC yol, eşleşme veya ham
  exception nesnesi yazmaz. Kullanıcıya gösterilecek hata metni RAM içi scan
  event'i olarak taşınır.
- Runtime credential, ccache, hedef, envanter ve bulgu için SQLite, dosya,
  cache veya başka kalıcı katman yoktur. Process kapanınca oturum kaybolur.

CCache ve yüklenen wordlist için genel multipart `UploadFile` akışına güvenmek
yerine ayrı bir raw-body upload endpoint'i kullanılmalı. İstek
`Request.stream()` ile parçalı okunur, uygulamanın kendi byte sayacı açık limite
ulaştığında akışı keser ve kabul edilen veri RAM'de scan session'a devredilir.
Starlette, `Request.stream()` kullanımında tüm body'nin bellekte
biriktirilmediğini belgeler
([request streaming](https://www.starlette.io/requests/)). Framework'te yerleşik
bir body-limit middleware varmış gibi davranılmayacak; limit bizim ASGI/route
katmanımızda test edilecektir. Bu seçim, multipart parser'ın olası
spool/temp-file davranışına bağımlı kalmamamızı sağlar.

> Buradaki “kalıcılık yok” tarama çalışma verisi içindir. Repo ile gelen default
> wordlist/share listeleri normal paket asset'leridir. Panelde yapılan liste
> düzenlemelerinin restart sonrasında korunması istenirse bu, ayrı ve açık bir
> **yapılandırma yazımıdır**; scan session veya web state persistence'ı değildir
> ve credential/bulgu kod yoluyla paylaşılmaz.

## Yerel araç olarak paketleme

- `src/` layout ve `pyproject.toml` kullanılır.
- `[project.scripts]` altında `nordis-smb-inspector` console entry point'i
  tanımlanır; PyPA bunu komut satırı araçları için standart akış olarak belgeler
  ([PyPA CLI packaging](https://packaging.python.org/en/latest/guides/creating-command-line-tools/)).
- Jinja template'leri ve yerel static asset'ler wheel package data'sına eklenir
  ve çalışma anında `importlib.resources` üzerinden çözülür; current working
  directory'ye bağlı olunmaz.
- Normal kurulum `pipx install .`; geliştirme kurulumu editable venv olabilir.
- CLI varsayılan portu açıkça belirler, yalnız `--port` değiştirilebilir. `--host`
  seçeneği sunulmaz. CLI URL'yi terminale yazar; tarayıcıyı otomatik açma isteğe
  bağlı olur.
- Web bağımlılıkları: `starlette`, `uvicorn`, `jinja2` ve task yönetimi doğrudan
  kullanıldığı için `anyio`. Form/file upload için `python-multipart` gerekmez;
  JSON ve raw streamed body kullanılır. Dağıtımda test edilen sürümler lock edilir.

## Web PoC planı

PoC gerçek SMB taraması yapmaz; sahte orchestrator ile web katmanını izole
doğrular.

1. Paket entry point'i Uvicorn'u tek worker ile `127.0.0.1` üzerinde, access log
   kapalı başlatsın; Jinja sayfasını ve paket içi static dosyaları sunsun.
2. Lifespan içinde RAM `ScanSession`, bounded event channel ve task group
   oluşturulsun.
3. Sahte scan; hedef hazırlama, TCP, auth, share, envanter ve içerik fazlarını
   üretip sayaç/target/file/finding olayları yayınlasın.
4. Panel snapshot'ı render etsin, SSE ile canlı güncellensin ve tabloları
   sayfalı çeksin. Browser storage API'lerinin hiçbiri kullanılmasın.
5. İptal POST'u cancel scope'u tetiklesin; sahte tarama açık kaynaklarını
   `finally` içinde kapatıp `scan.cancelled` durumuna geçsin.
6. Raw-body sahte ccache/wordlist yüklemesi body limitiyle RAM'de işlensin;
   geçici dosya oluşmadığı test edilsin.
7. Güvenlik/header, yeniden bağlanma, browser refresh ve graceful process
   shutdown senaryoları otomatik test edilsin.

### PoC kabul kontrolleri

- Dinlenen socket yalnız `127.0.0.1:<port>` olarak görünür.
- Her normal, hata ve SSE yanıtında `Cache-Control: no-store` vardır.
- GET/POST/SSE trafiği sırasında Uvicorn access log satırı oluşmaz.
- Aynı anda ikinci scan `409 Conflict` alır; birinci scan etkilenmez.
- Sayaçlar ve target/file olayları tam sayfa yenilemeden görünür.
- İptal düğmesi kısa sürede terminal `CANCELLED` durumunu üretir; scan task'ı ve
  sahte handle'lar açık kalmaz.
- SSE kesilip yeniden bağlandığında snapshot ile görünüm tutarlı hale gelir;
  scan kendiliğinden iptal olmaz.
- Browser Application/Storage görünümünde cookie, local/session storage,
  IndexedDB, Cache Storage ve service worker kaydı yoktur.
- Temp dizini yükleme öncesi/sonrası karşılaştırıldığında uygulamaya ait ccache,
  wordlist veya form dosyası oluşmaz.
- Process kapandıktan sonra credential, envanter veya bulgu dosyası bulunmaz.
- Wheel/pipx kurulumundan sonra template ve static asset yolları bağımsız bir
  çalışma dizininden açılır.

## Yeniden değerlendirme koşulu

İleride panel dışındaki istemciler için büyük, sürümlü ve tip güvenli bir REST
API/OpenAPI sözleşmesi istenirse FastAPI yeniden değerlendirilebilir. Mevcut
tek kullanıcılı yerel panel için Starlette gereken web özelliklerini zaten
sağlıyor; üst katmana ihtiyaç yok.
