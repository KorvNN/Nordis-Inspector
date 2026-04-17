# Wordlists

Nordis SMB Inspector iki ayrı liste türü kullanır:

- `content/`: Dosya içeriklerinde aranacak kelime ve ifadeler
- `shares/`: Doğrudan bağlantısı denenecek bilinen SMB share adları

Her satır tek bir girdidir. Boş satırlar ve `#` ile başlayan açıklama satırları
yok sayılır. Karşılaştırma varsayılan olarak büyük/küçük harf duyarsızdır.

Bu dosyalar uygulama yapılandırmasıdır. Credential, hedef, dosya envanteri veya
tarama bulguları bu dizine yazılmaz.

Varsayılan dosyalar kategori bazında düzenlenen normal `.txt` listeleridir.
Kalıp tabanlı algılama bunlardan bağımsızdır. Ayrıntılar için
[DETECTION.md](../docs/DETECTION.md) belgesine bakın.
