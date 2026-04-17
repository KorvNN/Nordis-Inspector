# Nordis SMB Inspector

Nordis SMB Inspector, yazılı olarak yetkilendirilmiş ağlarda erişilebilir SMB
paylaşımlarını envanterlemek ve desteklenen dosya içeriklerinde anahtar kelime
aramak için tasarlanan salt-okunur bir denetim aracıdır.

İlk ürün kapsamı [kapsam belgesinde](docs/SCOPE.md) v1.0 olarak kilitlenmiştir.
Uygulama kodu test edilebilir aşamalar halinde geliştirilmektedir.

## Mevcut geliştirme durumu

Yerel panel çalıştırılabilir durumdadır; IP/CIDR/hostname kapsamını doğrular,
genişletilmiş hedefleri önizler ve RAM içi tarama oturumu/SSE altyapısını sunar.
SMB ağ adaptörünün salt-okunur sözleşmeleri hazırdır; gerçek SMB bağlantı ve
dosya yürüyüşü henüz panele bağlanmamıştır.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/nordis-smb-inspector
```

Panel yalnız `http://127.0.0.1:8765` üzerinde açılır. Farklı bir loopback portu
için `--port` kullanılabilir; dış arayüzde dinleme seçeneği yoktur.

## Planlanan temel yetenekler

- CIDR veya tekil hedef listesiyle sınırlandırılmış SMB keşfi
- Virgülle karışık IP/CIDR hedef girişi
- Kerberos öncelikli, sonucu görünür SMB kimlik doğrulama
- Parola, NT hash ve Kerberos ccache credential girdileri
- Erişilebilen paylaşım, klasör ve dosyaların envanteri
- Hazır, yüklenen veya tarama sırasında genişletilen wordlist desteği
- Her hedef için bağlantı, SMB, kimlik doğrulama ve erişim durumları
- CIDR'dan üretilen IP'ler ile canlı faz/yüzde/sayaç görünümü
- Eşleşme olmasa da okunabilen ve okunamayan dosyaların envanteri
- Eşleşen satırın sistem, paylaşım, dosya ve konum bilgisiyle canlı gösterilmesi

Varsayılan listeler:

- [Hassas içerik terimleri](wordlists/content/default-sensitive.txt)
- [Bilinen SMB share adları](wordlists/shares/default-shares.txt)
- [Wordlist ve kalıp algılama tasarımı](docs/DETECTION.md)

> Bu proje yalnızca açıkça yetkilendirilmiş sistemlerde kullanılmak üzere
> geliştirilecektir. Parola deneme, yetki yükseltme veya dosya değiştirme
> işlevleri kapsam dışıdır.
