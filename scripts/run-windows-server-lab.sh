#!/usr/bin/env bash
set -euo pipefail

vm_root=${NORDIS_WINDOWS_VM_ROOT:-/home/kroven/VMs/ws2025}
iso_path=${NORDIS_WINDOWS_ISO:-/home/kroven/İndirilenler/Windows_Server_2025_EVAL_x64_en-us.iso}
disk_path="$vm_root/disk.qcow2"
vars_path="$vm_root/OVMF_VARS.4m.fd"
code_path=/usr/share/edk2/x64/OVMF_CODE.4m.fd

require_file() {
    if [ ! -f "$1" ]; then
        printf 'Gerekli dosya bulunamadı: %s\n' "$1" >&2
        exit 1
    fi
}

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo 'QEMU kurulu değil: sudo pacman -S --needed qemu-desktop edk2-ovmf' >&2
    exit 1
fi

if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    echo 'KVM erişilemiyor. kroven kullanıcısının kvm grubunda olduğunu doğrula ve yeniden oturum aç.' >&2
    exit 1
fi

require_file "$disk_path"
require_file "$vars_path"
require_file "$code_path"
require_file "$iso_path"

exec qemu-system-x86_64 \
    -name ws2025 \
    -enable-kvm \
    -machine pc,accel=kvm \
    -cpu host \
    -smp 2 \
    -m 4G \
    -uuid 3f431c79-a1da-4c6f-a92b-c4fac77c0030 \
    -drive "if=pflash,format=raw,readonly=on,file=$code_path" \
    -drive "if=pflash,format=raw,file=$vars_path" \
    -drive "file=$disk_path,format=qcow2,if=ide" \
    -drive "file=$iso_path,media=cdrom,readonly=on,if=ide" \
    -boot once=d,menu=on \
    -nic user,model=e1000,mac=52:54:00:77:00:30 \
    -device qemu-xhci,id=xhci \
    -device usb-tablet,bus=xhci.0 \
    -display gtk
