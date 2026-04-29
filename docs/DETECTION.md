# Nordis SMB Inspector — Wordlist ve Kalıp Algılama

Durum: **Uygulanan başlangıç kapsamı**

## 1. İki bağımsız arama yöntemi

Araç aynı decoded satırı iki yöntemle tarar:

1. **Wordlist:** Repo listesindeki ve tarama formundaki ek terimleri
   büyük/küçük harf duyarsız alt metin olarak arar.
2. **Kalıp:** Biçimi tanımlanabilen secret, token, anahtar ve credential
   artifact'lerini yerleşik Nordis kurallarıyla arar.

Kalıp algılama panelde tek seçenekle açılıp kapatılır. Wordlist'i üretmez veya
değiştirmez. Entropy tabanlı tahmin kullanılmaz.

## 2. Wordlist yönetimi

Repo iki normal UTF-8 metin dosyası sağlar:

- `wordlists/content/default-sensitive.txt`
- `wordlists/shares/default-shares.txt`

Panelde listeler görüntülenebilir, düzenlenebilir, `.txt` dosyasından içe
aktarılabilir ve repo dosyasına kalıcı kaydedilebilir. Tarama formundaki ek
terimler yalnız o tarama için kullanılır. Yorum ve boş satırlar çalıştırma
sırasında atlanır; aynı terimler casefold karşılaştırmasıyla tekilleştirilir.

Bir dosyada ilk sonuçta durulmaz. Aynı terimin satırdaki bütün konumları içerik
motorunda bulunur; panel her terim/satır eşleşmesini kaynak dosya ve tam satırla
gösterir.

## 3. Yerleşik kalıp kapsamı

`core/detection.py` içindeki sabit Nordis kural seti şu grupları kapsar:

- Cloud access key biçimleri
- JWT, Bearer ve Basic authentication değerleri
- Private key başlangıç blokları
- URL içindeki credential ve connection-string parolaları
- `.env`, JSON, YAML, XML, INI ve benzeri hassas alan/değer atamaları
- Group Policy Preferences `cpassword`
- Kerberos `$krb5tgs$`, `$krb5asrep$` ve `$krb5pa$` artifact'leri
- `LMHASH:NTHASH`, hesap/RID/hash ve NetNTLMv2 satırları
- DCC2, Unix crypt, bcrypt ve Argon2 hash biçimleri

Tek başına 32 hexadecimal karakter NT hash olarak raporlanmaz; MD5 veya başka
bir tanımlayıcı olabileceği için yapılandırılmış bağlam aranır. `changeme`,
`placeholder`, `example` ve benzeri yaygın örnek değerler hassas atama
kurallarında elenir.

Her kural benzersiz ID, başlık, kategori, regex ve `High`/`Medium` güven bilgisi
taşır. Regex'ler uygulama kodu yüklenirken derlenir; bozuk veya eksik metadata
başlangıçta açık hata üretir. Bir kuralın aynı satırda üretebileceği eşleşme
sayısı sınırlıdır.

## 4. Bulgu modeli

Her bulgu RAM içinde şu alanlarla tutulur:

- hedef, share ve dosya/arşiv üyesi yolu
- extracted fiziksel satır numarası ve tam satır
- `WORDLIST` veya `PATTERN` yöntemi
- wordlist terimi ya da kalıp başlığı
- kalıp bulgusunda kural ID, kategori ve güven seviyesi

Arşiv üyesi yolları `archive.zip!/folder/file` biçimindedir. PDF ve Office
belgelerinde satır numarası, extractor'ın ürettiği metin akışındaki fiziksel
satırı ifade eder; sayfa/hücre koordinatı olduğu iddia edilmez.

## 5. Güvenlik ve doğruluk

- Secret doğrulamak için üçüncü taraf API çağrısı yapılmaz.
- Harici secret-scanner binary'si veya çalışma zamanı internet bağlantısı yoktur.
- Kaynak satırları model `repr` değerlerinde redacted tutulur.
- Pattern pozitif/negatif örnekleri otomatik test edilir.
- Legacy encoding yalnız detector güven eşiğini geçtiğinde seçilir; belirsiz
  içerik tahmin edilmez ve `ENCODING_UNDETERMINED` olarak görünür.
- PDF/Office/arşiv çıkarıcıları disk dosyası oluşturmaz; remote range reader ve
  bellek akışlarıyla çalışır.
- Parolalı, bozuk veya sınırı aşan belgeler sessizce atlanmaz; dosya
  envanterinde güvenli hata kodu ve açıklaması gösterilir.

Entropy algılama, kullanıcı regex'i, allowlist editörü ve kategori bazlı kalıp
açma/kapatma mevcut ürün kapsamına dahil değildir.
