#!/usr/bin/env bash
set -euo pipefail

vm_root=${NORDIS_WINDOWS_VM_ROOT:-/home/kroven/VMs/ws2025}
version=0.1.285
release=1
installer_name="virtio-win-guest-tools-$version.exe"
installer_path="$vm_root/$installer_name"
image_path="$vm_root/virtio-win-guest-tools.img"
image_staging_path="$image_path.part"
installer_url="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-$version-$release/virtio-win-guest-tools.exe"
installer_sha256=c8b4a9fe87e1fc5d8e843495e082dea53420587fe04740b1084d85089343f04d

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Gerekli komut bulunamadı: %s\n' "$1" >&2
        exit 1
    fi
}

verify_installer() {
    local actual_sha256

    [ -f "$installer_path" ] || return 1
    actual_sha256=$(sha256sum "$installer_path")
    actual_sha256=${actual_sha256%% *}
    [ "$actual_sha256" = "$installer_sha256" ]
}

require_command curl
require_command mkfs.fat
require_command mcopy
require_command sha256sum
require_command truncate

mkdir -p "$vm_root"

if ! verify_installer; then
    printf 'VirtIO Windows guest tools %s indiriliyor...\n' "$version"
    curl -fL --retry 3 --output "$installer_path.part" "$installer_url"
    mv -f "$installer_path.part" "$installer_path"

    if ! verify_installer; then
        echo 'İndirilen guest tools dosyasının SHA-256 özeti beklenen değerle eşleşmiyor.' >&2
        exit 1
    fi
fi

truncate -s 64M "$image_staging_path"
mkfs.fat -F 32 -n GUESTTOOLS "$image_staging_path" >/dev/null
mcopy -o -i "$image_staging_path" "$installer_path" ::/virtio-tools.exe
mv -f "$image_staging_path" "$image_path"

printf 'Guest tools imajı hazır: %s\n' "$image_path"
echo 'Windows içinde GUESTTOOLS sürücüsünü açıp virtio-tools.exe dosyasını çalıştır.'
