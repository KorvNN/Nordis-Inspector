# Rules

Bu dizin Nordis SMB Inspector'ın içerik algılama kurallarını barındıracaktır.

Planlanan katmanlar:

- `content/`: Nordis kategorilerine ayrılmış bütün secret algılama kuralları
- `SOURCE_LOCK.yml`: İçe alınan kaynakların sürüm, commit ve checksum bilgileri
- `THIRD_PARTY_LICENSES.md`: Gerekli lisans ve attribution bildirimleri

Harici bir secret-scanner uygulaması çalışma zamanı bağımlılığı değildir. Nordis
kural motoru repo içine alınmış kuralları yerel olarak çalıştırır. Panel ve
bulgular bu birleşik yapıyı **Nordis Detection Rules** olarak gösterir.

Rule set henüz repo içine alınmamıştır. Kaynak sürümü ve entegrasyon testleri
kodlama aşamasında belirlendikten sonra kurallar Nordis kategorilerine dahil
edilecektir. Rule set ilk ürün sürümüyle sabitlenir; uygulama içinde otomatik
veya planlı upstream güncelleme mekanizması bulunmaz.
