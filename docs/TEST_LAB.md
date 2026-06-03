# Isolated Integration Lab

This guide builds a disposable SMB lab on a CachyOS/Arch Linux host. Nordis runs on
the host; a Samba VM and a Windows Server 2025 domain controller provide real SMB,
NTLM, SRVSVC, document, access-denial, and Kerberos behavior.

Use only synthetic data. Keep the lab disconnected from production networks and
revert VM snapshots after testing.

## Offline loopback smoke test

Before building VMs, run the rootless local smoke test:

```bash
.venv/bin/python scripts/run-local-smb-smoke.py
```

It creates a temporary read-only share on an ephemeral loopback port and exercises
real SMB2 negotiation, NTLM authentication, SRVSVC share discovery, directory
walking, bounded file reads, and canary detection. It uses synthetic data, needs no
internet connection, and removes the share when it exits.

This is a narrow protocol smoke test. It deliberately disables required signing and
secure negotiate because Impacket's embedded test server does not model a hardened
Windows target. Use the VM lab below for Windows, Kerberos, signing, encryption,
access-denial, timeout, and cancellation acceptance cases.

## Recommended topology

Create one libvirt network with no `<forward>` element:

| System | Address | Purpose | Practical allocation |
| --- | --- | --- | --- |
| CachyOS host | `10.77.0.1` | Runs Nordis | Existing host |
| `smb1` | `10.77.0.20` | CachyOS/Arch + Samba | 2 vCPU, 2–4 GiB RAM, 30 GiB |
| `dc1.nordis.test` | `10.77.0.30` | Windows Server 2025 + AD DS | 4 vCPU, 8 GiB RAM, 80 GiB |
| Unused address | `10.77.0.99` | Timeout case | No VM |

The VM allocations are practical lab estimates, not Microsoft minimum
requirements. The host is part of a libvirt isolated network, so Nordis can reach the
guests while the guests cannot reach the physical LAN.

## 1. Prepare CachyOS

Install the virtualization stack:

```bash
sudo pacman -S --needed qemu-full libvirt virt-manager virt-viewer dnsmasq \
  edk2-ovmf swtpm krb5
sudo systemctl enable --now libvirtd.service
sudo usermod -aG libvirt "$USER"
```

Log out and back in after changing group membership. Confirm that hardware
virtualization is available:

```bash
test -c /dev/kvm && echo "KVM is available"
virsh version
```

If `/dev/kvm` is absent, enable Intel VT-x or AMD-V in firmware and verify that the
appropriate KVM kernel module is loaded.

## 2. Create an isolated libvirt network

Save the following as `nordis-lab.xml`:

```xml
<network>
  <name>nordis-lab</name>
  <bridge name="virbr77" stp="on" delay="0"/>
  <domain name="nordis.test" localOnly="yes"/>
  <ip address="10.77.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.77.0.100" end="10.77.0.199"/>
    </dhcp>
  </ip>
</network>
```

Define and start it:

```bash
virsh net-define nordis-lab.xml
virsh net-autostart nordis-lab
virsh net-start nordis-lab
virsh net-dumpxml nordis-lab
```

There must be no `<forward>` element in the resulting XML. Do not attach these VMs
to a bridged production interface. If an OS needs downloads or Windows evaluation
activation, attach a separate default-NAT adapter temporarily, complete the work
before adding synthetic secrets, then remove that adapter and verify the VM has only
the `nordis-lab` NIC.

## 3. Build the Samba target

Create a CachyOS or Arch VM named `smb1`, attach only the isolated network, and set a
static address of `10.77.0.20/24`. Prepare the repository and virtual environment in
the VM before removing any temporary NAT adapter.

Run the fixture script inside `smb1`, replacing `ens3` with the VM's actual isolated
interface name:

```bash
sudo env \
  NORDIS_LAB_INTERFACES="lo ens3" \
  NORDIS_LAB_HOSTS_ALLOW="127.0.0.1 ::1 10.77.0.0/24" \
  NORDIS_LAB_TARGET="10.77.0.20" \
  ./scripts/setup-local-samba-lab.sh
```

The script is intentionally restricted to Arch-family disposable systems. It refuses
to replace an existing Samba configuration unless that file carries its management
marker. It creates:

- User `nordislab` with password `Password123!`
- Readable share `Public`
- Enumerated but denied share `Finance`
- Nested directories and an unreadable file
- Plain-text, synthetic NTLM, large streamed, PDF, DOCX, XLSX, PPTX, and ZIP fixtures

Verify from the host:

```bash
smbclient -L //10.77.0.20 -U 'WORKGROUP/nordislab%Password123!'
smbclient //10.77.0.20/Public -U 'WORKGROUP/nordislab%Password123!'
```

The fixture password is public and must never be reused outside this isolated lab.

## 4. Build Windows Server 2025

Download the official Windows Server 2025 evaluation ISO. Microsoft currently
provides ISO and VHD options; the evaluation lasts 180 days and must be activated
within the first 10 days to avoid automatic shutdown.

Create `dc1` in virt-manager with UEFI firmware and the `nordis-lab` network. A SATA
disk and emulated Intel NIC are the simplest installation path. For virtio disk or
network devices, attach a current `virtio-win` driver ISO and load the corresponding
driver during setup.

Install the Desktop Experience edition, rename the server to `dc1`, and assign:

- Address: `10.77.0.30/24`
- Gateway: blank while fully isolated
- DNS: `10.77.0.30`

In an elevated PowerShell session, install AD DS and create a new forest:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest `
  -DomainName "nordis.test" `
  -DomainNetbiosName "NORDIS" `
  -InstallDNS
```

After reboot, create a dedicated scan account and synthetic shares:

```powershell
$Password = Read-Host "Lab account password" -AsSecureString
New-ADUser `
  -Name "Nordis Scan" `
  -SamAccountName "nordisscan" `
  -UserPrincipalName "nordisscan@nordis.test" `
  -AccountPassword $Password `
  -Enabled $true

New-Item -ItemType Directory -Force C:\NordisLab\Public
New-Item -ItemType Directory -Force C:\NordisLab\Finance
Set-Content C:\NordisLab\Public\readable-match.txt `
  -Value "password = NORDIS_WINDOWS_CANARY"
Set-Content C:\NordisLab\Public\offline-hash-sample.txt `
  -Value "NTLM: 8846f7eaee8fb117ad06bdd830b7586c"
Set-Content C:\NordisLab\Public\unreadable-secret.txt `
  -Value "client_secret = NORDIS_DENIED_CANARY"

icacls C:\NordisLab\Public /inheritance:r `
  /grant:r "NORDIS\nordisscan:(OI)(CI)RX" "BUILTIN\Administrators:(OI)(CI)F"
icacls C:\NordisLab\Public\unreadable-secret.txt /inheritance:r `
  /grant:r "BUILTIN\Administrators:F"
icacls C:\NordisLab\Finance /inheritance:r `
  /grant:r "BUILTIN\Administrators:(OI)(CI)F"

New-SmbShare -Name Public -Path C:\NordisLab\Public `
  -ReadAccess "NORDIS\nordisscan" `
  -FullAccess "BUILTIN\Administrators"
New-SmbShare -Name Finance -Path C:\NordisLab\Finance `
  -FullAccess "BUILTIN\Administrators"
```

Use a unique disposable password when prompted. Confirm from Windows that SMB2/3 and
signing are enabled:

```powershell
Get-SmbServerConfiguration |
  Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature
Get-SmbShare | Select-Object Name, Path
```

Do not weaken domain security settings merely to make a test pass. Record any policy
that differs from the scanner's required signing and secure-negotiate defaults.

## 5. Prepare Kerberos on the host

Add a temporary lab-only name mapping:

```text
10.77.0.30 dc1.nordis.test dc1
```

Configure `/etc/krb5.conf` for the isolated realm:

```ini
[libdefaults]
    default_realm = NORDIS.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    NORDIS.TEST = {
        kdc = dc1.nordis.test
        admin_server = dc1.nordis.test
    }

[domain_realm]
    .nordis.test = NORDIS.TEST
    nordis.test = NORDIS.TEST
```

Kerberos is time-sensitive. Keep the host and `dc1` clocks synchronized before
disconnecting the temporary NAT adapter. Obtain a file-backed ccache:

```bash
KRB5CCNAME=FILE:/tmp/nordis-lab.ccache kinit nordisscan@NORDIS.TEST
KRB5CCNAME=FILE:/tmp/nordis-lab.ccache klist
```

Upload `/tmp/nordis-lab.ccache` in the Nordis ccache field and scan the hostname
`dc1.nordis.test`, not only the IP address. Remove the temporary cache after testing.

## 6. Run the acceptance matrix

Start Nordis on the host with `./run.sh`, then verify:

| Case | Input | Expected result |
| --- | --- | --- |
| Refused connection | `10.77.0.1` if port 445 is closed | `connection_refused` |
| Timeout | `10.77.0.99` | `timeout_no_response` |
| Samba password | `10.77.0.20`, lab password | SRVSVC lists `Public` and `Finance`; readable findings appear; denied objects produce partial access |
| Samba NT hash | `10.77.0.20`, NT-hash credential | NTLM succeeds without a password |
| Windows password | `dc1.nordis.test`, domain account | SMB 2/3 negotiates, SRVSVC lists both shares, Windows canary is found |
| Windows Kerberos | `dc1.nordis.test`, uploaded ccache | Kerberos attempt succeeds and no NTLM fallback is recorded |
| Empty/failed discovery | Controlled SRVSVC policy or injected test double | Empty success and enumeration failure remain distinct; no common shares are guessed |
| Cancellation | Stop during the large fixture | Terminal cancellation, no continuing result growth, handles close |

For the Samba NT-hash case, derive the hash only from the known disposable fixture
password:

```bash
.venv/bin/python -c 'from impacket.ntlm import compute_nthash; print(compute_nthash("Password123!").hex())'
```

`partial_access` is expected when at least one share or file is denied while other
inventory or findings were collected. The denied file's metadata may be visible, but
its canary must not appear because its content was never readable.

## 7. Regression checks

Run the local suite before and after live testing:

```bash
./scripts/check.sh
.venv/bin/python scripts/run-local-smb-smoke.py
```

Capture the application status values, negotiated dialect, authentication history,
and server configuration for failures. Do not capture real credentials or finding
lines. Revert both VMs to clean snapshots when the test cycle is complete.

## References

- [Windows Server 2025 Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025)
- [Install Windows Server](https://learn.microsoft.com/en-us/windows-server/get-started/install-windows-server)
- [Install Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
- [libvirt network XML](https://libvirt.org/formatnetwork.html)
- [libvirt domain XML](https://libvirt.org/formatdomain.html)
- [ArchWiki: QEMU](https://wiki.archlinux.org/title/QEMU)
