# Nordis SMB Inspector

Nordis SMB Inspector, SMB hedeflerini salt okunur inceleyen ve sonuçları yerel
bir web panelinde canlı gösteren Python uygulamasıdır.

## Mevcut yetenekler

- Virgül veya yeni satırla karışık IP, CIDR ve hostname hedefleri
- Yalnız gerçekten yanıt veren hedeflerin canlı durum tablosu; bağlantı reddi,
  SMB negotiation ve kimlik doğrulama sonuçlarının ayrı gösterimi
- SMB 2/3 dialect, signing ve encryption durumları
- Parola, NT hash ve Linux'ta RAM-backed `memfd` üzerinden ccache girdisi
- Auto (Kerberos, gerektiğinde NTLM), yalnız Kerberos ve yalnız NTLM akışları
- Impacket SRVSVC üzerinden gerçek share keşfi; keşif engellenirse repo
  wordlist'indeki bilinen share adlarını salt okunur bağlanma denemesiyle yoklama
- Erişilebilen klasör ve dosyaların, okunamayan öğeler dahil, envanteri
- Sabit 32 seviye sınırıyla recursive dosya ağacı yürüyüşü
- Dosyayı bütünüyle yerel diske almadan akışlı, büyük/küçük harf duyarsız metin
  araması; eşleşen her satır için terim ve satır numarası
- UTF BOM/UTF-8 ve güven eşiği geçen Windows legacy encoding algılama
- Metin katmanlı PDF; DOCX/XLSX/PPTX ve ODF belgeleri; ZIP/JAR/WAR/EAR,
  TAR ve GZIP arşivlerinde sınırlı, disk kullanmayan içerik çıkarma
- Wordlist'ten bağımsız JWT, private key, API anahtarı, yapılandırma ataması,
  Kerberos/NTLM ve yaygın credential artifact kalıpları
- İçerik ve share wordlist'lerini panelde görüntüleme, düzenleme, UTF-8 `.txt`
  içe aktarma ve repo dosyalarına kalıcı kaydetme
- Canlı faz, ilerleme, hedef, envanter ve bulgu sayaçları; ayrıntılı hata sonucu

Share adları kısa ömürlü ikinci bir Impacket oturumuyla SRVSVC üzerinden alınır;
dosya envanteri ve içerik okuma mevcut `smbprotocol` oturumunda kalır. SRVSVC
reddedilir veya kullanılamazsa hata hedef ayrıntısında gösterilir ve
[varsayılan share wordlist'indeki](wordlists/shares/default-shares.txt) adlar
  fallback olarak denenir.

Arşiv taraması en fazla 3 iç içe katman, 10.000 öğe ve toplam 500 MiB açılmış
içerikle sınırlıdır. Arşiv üyeleri envanter ve bulgularda
`archive.zip!/path/file` biçiminde görünür. Parolalı belgeler, OCR gerektiren
görüntü PDF'leri ve eski ikili DOC/XLS/PPT biçimleri içerik taramasına girmez;
dosyanın kendisi envanterde kalır ve ayrıştırma hatası açıkça gösterilir.

## Çalıştırma

```bash
./setup.sh
./run.sh
```

Panel yalnız `http://127.0.0.1:8765` üzerinde açılır. Farklı bir loopback portu
için `./run.sh --port 9000` kullanılabilir; dış arayüzde dinleme seçeneği yoktur.

Geliştirme/test bağımlılıkları ayrıca
`.venv/bin/pip install -e '.[dev]'` komutuyla kurulabilir.

## Yapılandırma girdileri

Paneldeki “Varsayılan listeler” bölümü bu iki repo dosyasını doğrudan yönetir:

- [Hassas içerik terimleri](wordlists/content/default-sensitive.txt)
- [Bilinen SMB share adları](wordlists/shares/default-shares.txt)

Kaydetme işlemi bu dosyaları diskte atomik olarak değiştirir; bir tarama
başlarken listelerin o anki sürümü okunur. Paneldeki “Ek arama terimleri” ise
yalnız o taramaya eklenir ve wordlist'i değiştirmez.

Ayrıntılı davranış ve test kaynakları:

- [Kapsam](docs/SCOPE.md)
- [İçerik algılama](docs/DETECTION.md)
- [İzole entegrasyon laboratuvarı](docs/TEST_LAB.md)
