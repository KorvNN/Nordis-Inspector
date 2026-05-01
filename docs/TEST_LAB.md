# Nordis SMB Inspector entegrasyon laboratuvarı

Doğrulama tarihi: **2026-08-13**

Bu belge, CachyOS/Arch tabanlı bir istemcide Nordis SMB Inspector'ın gerçek SMB
sunucularına karşı tekrar edilebilir entegrasyon testini tanımlar. İki ayrı
katman vardır:

1. standalone Samba ile TCP, NTLM, share, dosya ağacı ve içerik testleri;
2. ayrı bir AD DC sanal makinesiyle DNS, SPN, Kerberos ve ccache testleri.

Buradaki adresler yalnız örnek laboratuvar ağına aittir. Fiziksel şirket/ev
ağına bridge kullanma, üretim subneti girme veya laboratuvar dışındaki bir DNS
sunucusunu değiştirme. Sanal ağ internete yönlendirilmemelidir. Libvirt
kullanılıyorsa network XML'inde `<forward>` öğesinin olmaması ağı izole eder;
bu davranış [libvirt Network XML](https://libvirt.org/formatnetwork.html)
belgesinde tanımlanır.

## 1. Topoloji ve değişmez test değerleri

| Rol | Ad | Adres | İşlev |
|---|---|---:|---|
| Tarayıcı | `scan1` | `10.77.0.10` | CachyOS/Arch, repo ve web paneli |
| Standalone SMB | `smb1` | `10.77.0.20` | NTLM, share/tree/content fixture'ları |
| AD DC | `dc1.nordis.test` | `10.77.0.30` | DNS, KDC, CIFS SPN, NETLOGON/SYSVOL |
| Refused hedefi | `closed1` | `10.77.0.40` | Ayakta, fakat TCP/445 dinleyicisi yok |
| Timeout hedefi | `drop1` | `10.77.0.50` | Tarayıcıdan gelen TCP/445 SYN'lerini DROP eder |

AD değerleri:

```text
DNS domain: nordis.test
Kerberos realm: NORDIS.TEST
NetBIOS domain: NORDIS
Test kullanıcısı: nordisscan
```

`nordis.test` yalnız bu izole ağda çözülmelidir. `.local` kullanma; Samba AD DC
rehberi `.local` adının Avahi ile çakışabileceğini ayrıca belirtir. Her VM'i
hazırlamadan önce temiz bir snapshot al. Test bittiğinde tek tek hesap, dosya,
firewall kuralı veya Samba veritabanı silmek yerine snapshot'a dön. Bu belge
`rm -rf`, `userdel`, genel firewall flush veya production cleanup komutu vermez.

İlk doğrulamada `/24` CIDR taraması yapma. Şu kesin hedefleri tek tek kullan:

```text
10.77.0.20, 10.77.0.40, 10.77.0.50
```

AD senaryosunu daha sonra yalnız FQDN ile çalıştır:

```text
dc1.nordis.test
```

### 1.1 İzole libvirt ağı ve bağımsız ağ oracle'ı

Önce `nordis-lab` adında, `<forward>` öğesi bulunmayan bir libvirt ağı oluştur.
Aşağıdaki XML'i örneğin `nordis-lab.xml` adıyla kaydet:

```xml
<network>
  <name>nordis-lab</name>
  <bridge name="virbr77" stp="on" delay="0"/>
  <ip address="10.77.0.1" netmask="255.255.255.0"/>
</network>
```

```bash
sudo virsh net-define nordis-lab.xml
sudo virsh net-start nordis-lab
sudo virsh net-autostart nordis-lab
virsh net-dumpxml nordis-lab
```

`virsh net-dumpxml` çıktısında `<forward>` bulunmamalıdır. Bu, libvirt'in ağ
için NAT veya fiziksel ağa forwarding kurmadığını doğrulayan oracle'dır.

## 2. Paket hazırlığı ve izolasyona geçiş sırası

Paketleri ağ tamamen izole edildikten sonra kurmaya çalışma. Disposable Linux
VM'lerini başlangıçta yalnız geçici libvirt `default` NAT ağına bağla, sistemi
güncelle ve rol paketlerini kur. Ardından VM'leri kapat, NAT arayüzlerini çıkar,
yalnız `nordis-lab` arayüzünü bırak ve statik lab adreslerini ata. SMB/DC
servislerini ve fixture'ları ancak bu izolasyon doğrulandıktan sonra oluştur.

Sıra şöyledir:

1. geçici NAT ile VM'i kur ve paketleri indir;
2. VM'i kapat, `default` NAT NIC'ini kaldır ve yalnız `nordis-lab` NIC'ini bırak;
3. VM'i aç, statik lab adresini ve gerekiyorsa AD DNS'ini yapılandır;
4. aşağıdaki ağ oracle'larını çalıştır;
5. temiz snapshot al, sonra Samba/AD yapılandırmasına başla.

CachyOS, sistem paketleri için komut satırında `pacman` kullanılmasını önerir
([CachyOS FAQ](https://wiki.cachyos.org/cachyos_basic/faq/)). Rolling-release
sistemde partial upgrade yapma:

```bash
sudo pacman -Syu
```

Geçici NAT bağlıyken standalone VM'de:

```bash
sudo pacman -S samba smbclient
```

Tarayıcı VM'de SMB, Kerberos, DNS ve TCP oracle araçları:

```bash
sudo pacman -S smbclient krb5 bind openbsd-netcat
```

Samba AD DC seçilecekse DC VM'de, timeout fixture'ı VM'inde ise sırasıyla:

```bash
sudo pacman -S samba krb5 bind
sudo pacman -S nftables
```

Güncel paket adları Arch'ın resmî
[samba](https://archlinux.org/packages/extra/x86_64/samba/),
[smbclient](https://archlinux.org/packages/extra/x86_64/smbclient/),
[krb5](https://archlinux.org/packages/core/x86_64/krb5/) ve
[bind](https://archlinux.org/packages/extra/x86_64/bind/) sayfalarında
doğrulanabilir. `krb5` paketi `kinit`, `klist`, `kdestroy` ve `kvno` araçlarını
sağlar. Repo kurulumu tarayıcı VM'de şu şekilde yapılır:

```bash
./setup.sh
./run.sh
```

Panel `http://127.0.0.1:8765` üzerindedir. Paneli başka bir makineye açmak için
bind adresini değiştirme; tarayıcıyı `scan1` VM içinde çalıştır.

NAT arayüzleri çıkarıldıktan sonra libvirt hostunda:

```bash
virsh domiflist scan1
virsh domiflist smb1
virsh domiflist dc1
virsh net-dumpxml nordis-lab
```

Her VM yalnız `nordis-lab` ağına bağlı görünmeli ve network XML'inde hâlâ
`<forward>` bulunmamalıdır. Her Linux VM içinde `ip -4 route` çalıştır; yalnız
`10.77.0.0/24` bağlı rotası bulunmalı, `default via` satırı olmamalıdır.

Saat oracle'ı için `date -u '+%s %FT%TZ'` komutunu `scan1`, `smb1` ve `dc1`
üzerinde art arda çalıştır. Epoch değerleri arasındaki fark 300 saniyeden küçük
olmalıdır. Fark büyükse fixture'a geçmeden önce VM saatlerini hypervisor
üzerinden düzelt; dış NTP erişimi ekleme.

Samba ve refused/timeout fixture'ları kurulduktan sonra tarayıcı VM'deki TCP
firewall oracle'larını çalıştır:

```bash
nc -vz -w 3 10.77.0.20 445
nc -vz -w 3 10.77.0.40 445
nc -vz -w 3 10.77.0.50 445
```

Fixture'lar hazır olduğunda ilk komut başarılı, ikinci komut açıkça
`Connection refused`, üçüncü komut ise zaman aşımı vermelidir. Bu üç sonuç aynı
genel “başarısız” sonucuna indirgenmemelidir.

## 3. Standalone Samba fixture'ı

Bu katman bir disposable CachyOS/Arch VM'de hazırlanır. Aynı VM üzerinde yerel
test istenirse hedef `127.0.0.1` olabilir; aşağıdaki matris ağ sonuçlarını da
sınadığı için önerilen düzen ayrı `smb1` VM'idir.

Arch `samba` paketi `/etc/samba/smb.conf` dosyasını kendiliğinden oluşturmaz ve
standalone dosya sunucusu için doğru systemd birimi `smb.service`'tir.
`samba.service` AD DC içindir. `nmb.service`, NetBIOS discovery istenmiyorsa
gerekmez. Bunlar [ArchWiki Samba](https://wiki.archlinux.org/title/Samba) ve
[paket dosya listesinde](https://archlinux.org/packages/extra/x86_64/samba/files/)
doğrulanmıştır.

### 3.1 Hesap ve dizinler

`nordislab` yalnız bu VM'de kullanılan bir hesaptır. Unix oturum parolası
gerekmez; `/usr/bin/nologin` shell'iyle yerel hesap yalnız dosya sahipliği ve
Samba passdb eşlemesi için vardır. `smbpasswd` isteminde lab-only
`Password123!` değerini gir. Parola komut satırı argümanına yazılmaz.

```bash
sudo useradd -M -s /usr/bin/nologin nordislab
sudo smbpasswd -a nordislab
sudo install -d -m 0750 -o nordislab -g "$(id -gn nordislab)" /srv/samba/nordis-public
sudo install -d -m 0750 -o nordislab -g "$(id -gn nordislab)" /srv/samba/nordis-denied
```

Standalone Samba'da hesabın önce işletim sisteminde, sonra Samba hesap
veritabanında bulunması gerekir; ayrıntılar resmî
[standalone server rehberinde](https://wiki.samba.org/index.php/Setting_up_Samba_as_a_Standalone_Server)
ve [`smbpasswd` man sayfasında](https://www.samba.org/samba/docs/current/man-html/smbpasswd.8.html)
yer alır.

### 3.2 İçerik ve erişim fixture'ları

Eşleşen ve eşleşmeyen iki okunabilir dosya oluştur:

```bash
sudo -u nordislab sh -c 'printf "%s\n" \
  "ordinary laboratory line" \
  "password = NORDIS_LAB_CANARY_ONE" \
  "ordinary second line" \
  "PASSWORD = NORDIS_LAB_CANARY_TWO" \
  > /srv/samba/nordis-public/readable-match.txt'

sudo -u nordislab sh -c 'printf "%s\n" \
  "ordinary laboratory text" \
  "this file intentionally has no selected term" \
  > /srv/samba/nordis-public/readable-no-match.txt'
```

Share listelenebildiği halde açılamayan bir dosya oluştur. Bu dosya envanterde
görünmeli, içerik okuması `FILE_READ_DENIED` olmalıdır:

```bash
sudo install -m 000 -o root -g root /dev/null /srv/samba/nordis-public/unreadable.txt
```

64 MiB civarında, sonuna doğru tek eşleşmesi bulunan metin dosyası streaming
okumayı doğrular. Dosya RAM'e veya yerel geçici dosyaya bütünüyle alınmamalıdır:

```bash
sudo -u nordislab sh -c '
  yes "ordinary streamed laboratory line" | head -c 67108864 \
    > /srv/samba/nordis-public/large-stream.txt
  printf "\npassword = NORDIS_LAB_STREAM_CANARY\n" \
    >> /srv/samba/nordis-public/large-stream.txt
'
```

### 3.3 `smb.conf`

`<LAB_IFACE>` değerini yalnız izole `10.77.0.0/24` ağına bağlı arayüz adıyla
değiştir. Örnek ayar SMB1'i açmaz, yalnız TCP/445 dinler ve signing'i zorunlu
tutar:

```ini
[global]
    server role = standalone server
    workgroup = WORKGROUP
    security = user
    map to guest = never
    logging = systemd
    log level = 1
    smb ports = 445
    interfaces = lo <LAB_IFACE>
    bind interfaces only = yes
    hosts allow = 127.0.0.1 10.77.0.0/24
    hosts deny = ALL
    server min protocol = SMB2_02
    server max protocol = SMB3_11
    server signing = mandatory

[Public]
    path = /srv/samba/nordis-public
    browseable = yes
    read only = yes
    valid users = nordislab

[Finance]
    path = /srv/samba/nordis-denied
    browseable = yes
    read only = yes
    invalid users = nordislab
```

`Public` ve `Finance`, Impacket'in kısa ömürlü ikinci SMB oturumundan yaptığı
SRVSVC enumeration ile keşfedilir. Enumeration reddedildiğinde hedef satırında
`SHARE_ENUM_DENIED` görünür ve paylaşım denenmez. Parametrelerin güncel anlamları için
[`smb.conf(5)`](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)
kullanılmalıdır. Samba, SMB2 için signing desteği bulunduğunu ve `mandatory`
girdisinin istemciyi imzaya zorladığını belgeler.

Repo içindeki `scripts/setup-local-samba-lab.sh`, düz metin fixture'larına ek
olarak DOCX, XLSX, PPTX, metin katmanlı PDF ve iç içe ZIP canary dosyalarını da
`Public` share'ine kurar. Sistem dizini yazımı gerektiğinden betik kullanıcı
tarafından `sudo ./scripts/setup-local-samba-lab.sh` ile çalıştırılır.

Her değişiklikten sonra yapılandırmayı doğrula, sonra standalone birimini başlat:

```bash
sudo testparm -s /etc/samba/smb.conf
sudo testparm -s --parameter-name='server signing' /etc/samba/smb.conf
sudo systemctl start smb.service
systemctl is-active smb.service
```

İkinci `testparm` komutunun normalize edilmiş çıktısı `required` olmalıdır;
yapılandırma girdisindeki `mandatory` kelimesini aynen geri bekleme.

`testparm` yalnız yapılandırmanın iç tutarlılığını kontrol eder; servisin gerçekten
erişilebilir olduğunu garanti etmez
([resmî `testparm` belgesi](https://www.samba.org/samba/docs/current/man-html/testparm.1.html)).
Tarayıcı VM'den ayrı bir oracle testi çalıştır:

```bash
smbclient -L 10.77.0.20 -U 'WORKGROUP\nordislab' -m SMB3 --client-protection=sign
smbclient //10.77.0.20/Public -U 'WORKGROUP\nordislab' -m SMB3 \
  --client-protection=sign -c 'ls'
```

Parolayı istemde gir. `smbclient` seçenekleri güncel
[`smbclient(1)`](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
belgesindedir. Standalone VM'de UFW etkinse yalnız tarayıcı VM'in adresine izin
ver:

```bash
sudo ufw status verbose
sudo ufw allow proto tcp from 10.77.0.10 to any port 445
```

Bu kural fiziksel LAN CIDR'ına genişletilmemelidir.

### 3.4 Refused ve timeout hedefleri

`closed1` temiz bir VM olmalı ve 445'te hiçbir süreç dinlememelidir:

```bash
ss -ltn '( sport = :445 )'
```

Boş çıktı aldıktan sonra VM açık bırakılır. Kernel gelen SYN'e RST verdiği için
uygulama bunu `CONNECTION_REFUSED` olarak ayırabilmelidir. `scan1` üzerindeki
bağımsız oracle:

```bash
nc -vz -w 3 10.77.0.40 445
```

Komutun stderr çıktısı `Connection refused` içermeli ve exit code sıfırdan
farklı olmalıdır. DNS hatası veya timeout bu fixture için doğru sonuç değildir.

`drop1` ayrı bir disposable VM'dir. Aşağıdaki nftables tablosu yalnız
`scan1 -> TCP/445` trafiğini sessizce düşürür; kural kalıcı dosyaya kaydedilmez:

```bash
sudo nft add table inet nordis_lab
sudo nft 'add chain inet nordis_lab input { type filter hook input priority -10; policy accept; }'
sudo nft add rule inet nordis_lab input ip saddr 10.77.0.10 tcp dport 445 drop
sudo nft list table inet nordis_lab
```

Sözdizimi [`nft(8)`](https://man.archlinux.org/man/nft.8.en) ile doğrulanmıştır.
Temizlik için global ruleset'i flush etme; disposable VM snapshot'ına dön.

## 4. AD/Kerberos katmanı

AD DC, standalone `smb1` ile aynı VM olmamalıdır. Birincil seçenek temiz bir
Samba AD DC VM'i, alternatif ise Windows Server AD DS VM'idir. Yalnız birini
kurmak yeterlidir.

### 4.1 Seçenek A: Samba AD DC

Temiz Arch/CachyOS VM'de bölüm 2'de paketler kurulup NAT arayüzü çıkarıldıktan
sonra hostname'i ayarla:

```bash
sudo hostnamectl hostname dc1.nordis.test
```

VM'e `10.77.0.30/24` statik adres ver. `/etc/hosts` içinde bu adres hem FQDN hem
kısa ada çözülmelidir:

```text
10.77.0.30 dc1.nordis.test dc1
```

Provisioning öncesinde eski bir standalone `/etc/samba/smb.conf` varsa onu
silme; snapshot'a dön veya `smb.conf.pre-ad` adıyla kenara taşı. Ardından resmî
interaktif provisioning akışını kullan:

```bash
sudo samba-tool domain provision --use-rfc2307 --interactive
```

İstemlerde şunları seç:

```text
Realm: NORDIS.TEST
Domain: NORDIS
Server role: dc
DNS backend: SAMBA_INTERNAL
DNS forwarder: none
Administrator password: <yalnız bu lab için güçlü parola>
```

Samba provisioning sonunda ürettiği `krb5.conf` yolunu gösterir. O dosyayı DC
VM'in `/etc/krb5.conf` dosyasına kopyala; sembolik bağ kurma. Sonra DC'nin DNS
resolver'ını kendi `10.77.0.30` adresine yönelt ve paket birimini başlat:

```bash
lab_generated_krb5_conf=/path/printed/by/provision/krb5.conf
sudo install -m 0644 "$lab_generated_krb5_conf" /etc/krb5.conf
sudo systemctl start samba.service
systemctl is-active samba.service
sudo samba-tool user create nordisscan
```

`samba-tool user create` parola verilmezse istemde parola alır; lab parolasını
komut satırına koyma. Samba AD'nin fresh-install, DNS ve Kerberos gereksinimleri
resmî [AD DC kurulum rehberinde](https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller),
komutlar ise [`samba-tool(8)`](https://www.samba.org/samba/docs/current/man-html/samba-tool.8.html)
sayfasında açıklanır.

DC üzerinde temel kontrol:

```bash
sudo samba-tool domain level show
sudo samba-tool spn list 'DC1$'
smbclient -L localhost -U 'NORDIS\Administrator'
```

`NETLOGON`, `SYSVOL` ve `IPC$` görünmelidir.

### 4.2 Seçenek B: Windows Server AD DS

Windows Server VM'in hostname'ini `DC1`, statik adresini `10.77.0.30/24` yap ve
yalnız izole sanal switch'e bağla. Elevated PowerShell'de:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "nordis.test" -DomainNetbiosName "NORDIS" -InstallDNS
```

İkinci komut DSRM parolasını güvenli istemde alır ve promotion sonunda VM'i
yeniden başlatabilir. Akış Microsoft'un
[AD DS kurulum](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
ve [`Install-ADDSForest`](https://learn.microsoft.com/en-us/powershell/module/addsdeployment/install-addsforest?view=windowsserver2025-ps)
belgelerine dayanır. Reboot sonrasında test hesabını parola komut satırına
yazmadan oluştur:

```powershell
$LabPassword = Read-Host "nordisscan lab password" -AsSecureString
New-ADUser -Name "Nordis Scan" -SamAccountName "nordisscan" `
  -UserPrincipalName "nordisscan@nordis.test" `
  -AccountPassword $LabPassword -Enabled $true
```

SPN'leri salt okunur sorgula:

```powershell
setspn -L DC1
setspn -Q cifs/dc1.nordis.test
setspn -X
```

SPN'yi otomatik olarak ekleme. Microsoft, bilgisayar domain'e katıldığında
standart SPN'lerin normalde otomatik kaydedildiğini ve eklemek gerekirse duplicate
kontrolü yapan `-S` biçiminin kullanılmasını söyler
([`setspn` belgesi](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn)).
Bu laboratuvarda gerçek oracle, istemciden `kvno cifs/dc1.nordis.test`
komutunun başarılı olmasıdır.

Domain kullanıcısıyla oturum açmış ayrı bir Windows istemci kullanılıyorsa aynı
service ticket şu salt okunur komutlarla denetlenebilir:

```powershell
klist get cifs/dc1.nordis.test
klist
```

Microsoft [`klist`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist)
belgesi `get` alt komutunun belirli bir SPN için ticket istediğini açıklar.

### 4.3 Tarayıcı VM'de DNS, saat ve Kerberos ön kontrolü

`scan1` resolver'ında tek AD DNS sunucusu `10.77.0.30`, search domain ise
`nordis.test` olmalıdır. Bu ayarı yalnız izole VM bağlantı profiline uygula.
Önce doğrudan DC DNS'ini sorgula:

```bash
host -t SRV _kerberos._udp.nordis.test 10.77.0.30
host -t SRV _ldap._tcp.nordis.test 10.77.0.30
host -t A dc1.nordis.test 10.77.0.30
getent ahostsv4 dc1.nordis.test
```

SRV cevapları `dc1.nordis.test`, A cevabı `10.77.0.30` göstermelidir. AD'nin
KDC/DC keşfi için AD DNS zone'unu çözebilen resolver kullanması gerektiği Samba
AD DC rehberinde açıklanır.

DNS ve firewall ayrımını ayrıca doğrula:

```bash
nc -vz -w 3 dc1.nordis.test 53
nc -vz -w 3 dc1.nordis.test 88
nc -vz -w 3 dc1.nordis.test 445
```

Üç TCP bağlantısı da başarılı olmalıdır. `host` sorgusu başarısızsa DNS
yapılandırmasını, isim doğru çözülüp `nc` başarısızsa servis/firewall durumunu
incele; bunları tek bir Kerberos hatası olarak yorumlama.

Tarayıcı VM'in `/etc/krb5.conf` dosyasında şu lab realm'i bulunmalıdır:

```ini
[libdefaults]
    default_realm = NORDIS.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false

[domain_realm]
    .nordis.test = NORDIS.TEST
    nordis.test = NORDIS.TEST
```

DC, tarayıcı ve SMB hedefinin saatleri beş dakikadan daha yakın olmalıdır.
Microsoft'un güncel
[Kerberos troubleshooting rehberi](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance)
bu sınırı açıkça belirtir.

```bash
date -u '+%s %FT%TZ'
```

Komutu `scan1` ve Samba DC üzerinde art arda çalıştır; ilk sütundaki epoch
değerlerinin farkı 300 saniyenin altında olmalıdır. Windows DC kullanılıyorsa
DC'deki karşılık gelen oracle `Get-Date -AsUTC` çıktısıdır.

FILE tipinde, kullanıcı oturumunun volatile runtime dizininde bir lab cache'i
oluştur ve CIFS service ticket'ını önceden doğrula:

```bash
export KRB5CCNAME="FILE:/run/user/$(id -u)/nordis-lab.ccache"
kinit -c "$KRB5CCNAME" nordisscan@NORDIS.TEST
klist -c "$KRB5CCNAME"
kvno cifs/dc1.nordis.test
klist -c "$KRB5CCNAME"
smbclient //dc1.nordis.test/NETLOGON \
  --use-krb5-ccache="$KRB5CCNAME" --use-kerberos=required -c 'ls'
```

`klist` çıktısında önce `krbtgt/NORDIS.TEST`, `kvno` sonrasında ayrıca
`cifs/dc1.nordis.test` bulunmalıdır. `smbclient` parola istemeden başarılı olup
NETLOGON içeriğini listelemelidir; bu, panelden bağımsız ccache/SMB oracle'ıdır.
`KRB5CCNAME=TYPE:residual` biçimi ve FILE cache davranışı MIT Kerberos'un
[credential cache](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
belgesinde tanımlanır. Cache bir parola değildir ama geçerli ticket içerdiği
için secret gibi korunmalıdır. Testten sonra ilgili cache'i geçersiz kıl:

```bash
kdestroy -c "$KRB5CCNAME"
```

## 5. Panel test akışları

Tarama öncesinde “Wordlist yönetimi” bölümünde içerik listesinin metni ile kayıt
sayısı görünmelidir. Editörde yapılan değişiklik veya UTF-8 `.txt` içe aktarma,
ancak `Kaydet` düğmesine basıldığında repo wordlist'ine kalıcı yazılır. “Ek
arama terimleri” alanı ise yalnız o taramaya
eklenir. Panel bir maksimum derinlik alanı sunmaz; recursive yürüyüş kod içindeki
sabit 32 seviye sınırını kullanır.

### 5.1 Standalone toplu bağlantı testi

Panel girdileri:

```text
Hedefler: 10.77.0.20, 10.77.0.40, 10.77.0.50
Domain: WORKGROUP
Kullanıcı: nordislab
Credential: Parola
Parola: Password123!
Kimlik doğrulama: Yalnız NTLM
İçerik terimleri: repo varsayılan listesi otomatik kullanılır
Ek terim: NORDIS_LAB_STREAM_CANARY
```

Beklenen hedef görünümü:

- `10.77.0.20`: TCP açık, SMB negotiate ve NTLM authentication başarılı;
- `10.77.0.40`: gerçek yanıt veren host olarak `CONNECTION_REFUSED` satırı;
- `10.77.0.50`: `TIMEOUT_NO_RESPONSE` iç sonucu, fakat yanıt veren hedef
  tablosunda ve envanterde satır yok.

CIDR'daki olası adres sayısı cihaz sayısı değildir. Bu testte panel `254 cihaz`
gibi bir sayı üretmemeli ve `10.77.0.0/24` içindeki denenmemiş/yanıtsız adresleri
tek tek göstermemelidir.

### 5.2 Yanlış parola

Aynı standalone hedefe yalnız bir kez, `DefinitelyWrong-Lab-Only` parolasıyla
NTLM-only tarama başlat. TCP ve SMB negotiation başarılı, authentication
`AUTH_FAILED` olmalıdır. Hedef `timeout`, `refused` veya `SMB yok` diye
etiketlenmemelidir. Hesap kilitleme davranışıyla karışmaması için hatalı parola
testini döngüye alma.

### 5.3 NT hash ile NTLM

Bu fixture'da `Password123!` parolasının NT hash değeri:

```text
2b576acbe6bcfda7294d6bd18041b8fe
```

Panelde credential türünü `NT hash`, auth modunu `Yalnız NTLM` seç. Domain
`WORKGROUP`, kullanıcı `nordislab` ve hedef `10.77.0.20` olmalıdır. Sonuçta
seçilen mekanizma yalnız `NTLM` görünmeli; Kerberos denemesi/fallback kaydı
oluşmamalıdır. Bu değer yalnız disposable fixture hesabına aittir ve başka bir
hesapta kullanılmamalıdır.

Panelden önce aynı hash'i bağımsız `smbclient` oracle'ıyla doğrula:

```bash
smbclient -L 10.77.0.20 -U 'WORKGROUP\nordislab' --pw-nt-hash -m SMB3
```

Parola istemine `2b576acbe6bcfda7294d6bd18041b8fe` yaz. Komut başarılı olup
`Public` share'ini göstermelidir. `--pw-nt-hash` olmadan aynı değer bir düz
metin parola olarak yorumlanacağı için geçerli oracle değildir.

### 5.4 Parola Auto ile Kerberos

Panel girdileri:

```text
Hedef: dc1.nordis.test
Domain/realm: NORDIS.TEST
Kullanıcı: nordisscan
Credential: Parola
Kimlik doğrulama: Auto
```

IP adresi girme. Kerberos'un hedef kimliği `cifs/dc1.nordis.test` SPN'idir;
Microsoft da signing/Kerberos için share'e IP ile bağlanılmamasını önerir
([SMB signing rehberi](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)).
Beklenen sonuç ilk denemede `KERBEROS` seçilmesi, NTLM fallback olmaması ve en
az `NETLOGON`, `SYSVOL`, `IPC$` sonuçlarının görünmesidir.

### 5.5 Ccache testi

CCache entegrasyonu ancak şu koşullar birlikte sağlandığında PASS sayılır:

1. panel `.ccache` baytlarını credential olarak kabul eder;
2. baytlar kalıcı dosyaya/loga yazılmaz;
3. adapter bunları Kerberos-only oturumda gerçekten kullanır;
4. hedef FQDN ve seçilen mekanizma `KERBEROS` olarak raporlanır;
5. hatada sessiz NTLM fallback yapılmaz.

4.3'te üretilen `/run/user/<uid>/nordis-lab.ccache` dosyasını
yükle, hedefi `dc1.nordis.test` seç ve ccache içindeki `nordisscan@NORDIS.TEST`
principal'ıyla `NETLOGON` erişimini doğrula. Cache yalnız Linux RAM-backed memfd
üzerinden Kerberos'a aktarılır; temp-file fallback yoktur. 4.3'teki Kerberos
zorunlu `smbclient --use-krb5-ccache` komutu aynı cache için bağımsız oracle'dır.

## 6. Kabul test matrisi

`Beklenen panel sonucu` sütunundaki sabit durum adları uygulamanın normalize
edilmiş sonuç sözleşmesidir. Sunucu oracle'ı ile panel farklı şey söylüyorsa test
başarısızdır.

| ID | Fixture / girdi | Beklenen panel sonucu | Bağımsız oracle |
|---|---|---|---|
| NET-OPEN | `10.77.0.20:445` | `PORT_OPEN`, ardından SMB negotiation ve auth | `smbclient -L 10.77.0.20 ...` başarılı |
| NET-REFUSED | `10.77.0.40:445`, listener yok | `CONNECTION_REFUSED`; yanıt veren hedef satırı var, envanter yok | `nc -vz -w 3 10.77.0.40 445` açıkça `Connection refused` |
| NET-TIMEOUT | `10.77.0.50:445`, nft DROP | `TIMEOUT_NO_RESPONSE`; hedef/envanter satırı yok | `nft list table inet nordis_lab` DROP kuralını gösterir |
| AUTH-WRONG | `nordislab` + tek yanlış parola | SMB'ye kadar gelir, sonra `AUTH_FAILED` | Doğru parola ile hemen sonraki `smbclient` başarılı |
| AUTH-KRB-AUTO | `dc1.nordis.test`, password + Auto | İlk deneme Kerberos başarılı; selected mechanism `KERBEROS`, fallback yok | `kvno cifs/dc1.nordis.test` ve `klist` başarılı |
| AUTH-NT-HASH | Standalone lab hash + NTLM-only | Tek mekanizma `NTLM`, authenticated | `smbclient ... --pw-nt-hash` aynı hash ile başarılı |
| AUTH-CCACHE | FILE ccache upload + FQDN | Kerberos-only başarılı; fallback yok | `smbclient ... --use-krb5-ccache ... --use-kerberos=required` başarılı |
| SHARE-OK | Wordlist'te bulunan `Public` | Share `CONNECTED`; tree walk başlar | `smbclient //10.77.0.20/Public ... -c 'ls'` başarılı |
| SHARE-DENIED | `Finance`, `invalid users = nordislab` | Share görünür ve `SHARE_ACCESS_DENIED`; içerik zorlanmaz | `smbclient //10.77.0.20/Finance ...` access denied |
| FILE-DENIED | `Public/unreadable.txt`, mode `000` | Dosya envanterde, `FILE_READ_DENIED`, bulgu yok | `Public` listelenir ama dosya `get` işlemi reddedilir |
| CONTENT-MATCH | `readable-match.txt`, case-insensitive `password` | Satır 2 ve 4 ayrı bulgu; tam satır ve dosya/share/host yolu görünür | Fixture içeriğiyle karşılaştır |
| CONTENT-NO-MATCH | `readable-no-match.txt` | Dosya `FILE_READABLE` olarak envanterde kalır; bulgu yok | `smbclient ... -c 'get ...'` okunabilir |
| CONTENT-STREAM | Yaklaşık 64 MiB `large-stream.txt` | Range/chunk okuma tamamlanır, sondaki canary bulunur; bütün dosya yerel kopyaya dönüşmez | `smbclient ls` boyutu ve fixture'ın son satırı |
| SMB-SIGN | `server signing = mandatory` girdisi | Signing `supported=true`, `required=true`, authenticated session'da `active=true` | `testparm --parameter-name='server signing'` -> `required` |
| SMB-DIALECT | Min `SMB2_02`, max `SMB3_11` | Dialect `3.1.1`; SMB1 sonucu üretilmez | `testparm` min/max değerleri; Windows seçeneğinde `Get-SmbConnection` |

Windows Server seçeneğinde bağlantı açıldıktan sonra dialect/signing oracle'ı:

```powershell
Get-SmbConnection | Format-List ServerName,ShareName,Dialect,Signed,Encrypted
Get-SmbServerConfiguration | Format-List RequireSecuritySignature
```

`Get-SmbConnection` istemcinin kurduğu SMB bağlantılarını ve dialect'i gösterir
([Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbconnection?view=windowsserver2025-ps)).
Signing gereksiniminin sorgulanması Microsoft'un
[SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
rehberinde belgelenmiştir.

## 7. Geçiş ölçütleri

Bir entegrasyon koşusu ancak aşağıdakilerin tamamı doğruysa PASS sayılır:

- canlı faz `COMPLETED` olmadan önce TCP, authentication, share, inventory ve
  content aşamaları gerçekten tamamlanır;
- refused, timeout ve access denied aynı genel hata altında birleşmez;
- başarısız bir hedef yalnız “Başarısız” demez; hata fazını ve mevcutsa
  normalize durum kodu, sembolik hata adı, ham hata kodu ve güvenli hata
  açıklamasını gösterir;
- yalnız gerçek yanıt veren adresler hedef tablosuna girer;
- eşleşmesiz ve okunamayan dosyalar da envanterde kalır;
- aynı dosyadaki bütün eşleşmeler doğru satır numarasıyla görünür;
- kullanılan auth mekanizması gerçek sonuçtur; Auto fallback geçmişi gizlenmez;
- dialect ile signing `supported`, `required` ve `active` durumları birbirine
  karıştırılmaz;
- ccache yalnız Kerberos ile çalışır ve temp-file/NTLM fallback üretmez.

Test sonuçları uygulamanın süreç belleğinde kalır. Fixture parolaları, NT hash,
ccache veya eşleşen satırlar terminal/debug/access loglarına kopyalanmamalıdır.
Laboratuvar kapatılırken servisleri ve ağ kurallarını üretim hostunda tek tek
silmek yerine disposable VM'leri kapatıp bilinen temiz snapshot'a dön.
