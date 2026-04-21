# Nordis SMB Inspector

Nordis SMB Inspector, yazılı olarak yetkilendirilmiş ağlarda erişilebilir SMB
paylaşımlarını envanterlemek ve desteklenen dosya içeriklerinde anahtar kelime
aramak için tasarlanan salt-okunur bir denetim aracıdır.

İlk ürün kapsamı [kapsam belgesinde](docs/SCOPE.md) v1.0 olarak kilitlenmiştir.
Uygulama kodu test edilebilir aşamalar halinde geliştirilmektedir.

## Mevcut geliştirme durumu

Yerel panel çalıştırılabilir durumdadır; IP/CIDR/hostname kapsamındaki TCP/445
erişimini canlı tarar ve yalnız yanıt verdiği doğrulanan IP'leri durum tablosuna
ekler. SMB 2/3 negotiation ile parola/NT-hash authentication adaptörleri hazırdır;
bu aşamalar ve dosya yürüyüşü henüz panel taramasına bağlanmamıştır.

```bash
./setup.sh
./run.sh
```

Panel yalnız `http://127.0.0.1:8765` üzerinde açılır. Farklı bir loopback portu
için `./run.sh --port 9000` kullanılabilir; dış arayüzde dinleme seçeneği yoktur.

Geliştirme/test bağımlılıkları ayrıca
`.venv/bin/pip install -e '.[dev]'` komutuyla kurulabilir.

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
