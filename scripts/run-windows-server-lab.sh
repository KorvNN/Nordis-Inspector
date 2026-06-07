#!/usr/bin/env bash
set -euo pipefail

vm_root=${NORDIS_WINDOWS_VM_ROOT:-/home/kroven/VMs/ws2025}
iso_path=${NORDIS_WINDOWS_ISO:-/home/kroven/İndirilenler/Windows_Server_2025_EVAL_x64_en-us.iso}
disk_path="$vm_root/disk.qcow2"
vars_path="$vm_root/OVMF_VARS.4m.fd"
guest_tools_image=${NORDIS_WINDOWS_GUEST_TOOLS_IMAGE:-$vm_root/virtio-win-guest-tools.iso}
lab_bridge=${NORDIS_WINDOWS_LAB_BRIDGE:-virbr77}
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

if ! command -v remote-viewer >/dev/null 2>&1; then
    echo 'SPICE görüntüleyici kurulu değil: sudo pacman -S --needed virt-viewer' >&2
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
require_file "$guest_tools_image"

if [ ! -d "/sys/class/net/$lab_bridge" ]; then
    echo "İzole lab bridge'i hazır değil: $lab_bridge" >&2
    echo 'Ağı başlat: sudo virsh -c qemu:///system net-start efelab' >&2
    exit 1
fi

if ! grep -Fqx "allow $lab_bridge" /etc/qemu/bridge.conf 2>/dev/null; then
    echo "QEMU bridge izni eksik: /etc/qemu/bridge.conf dosyasına 'allow $lab_bridge' ekle." >&2
    exit 1
fi

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
    -netdev "bridge,id=efelab,br=$lab_bridge" \
    -device e1000,netdev=efelab,mac=52:54:00:77:00:31 \
    -device qemu-xhci,id=xhci \
    -device usb-tablet,bus=xhci.0 \
    -drive "file=$guest_tools_image,format=raw,media=cdrom,readonly=on,if=ide" \
    -device virtio-serial-pci \
    -chardev spicevmc,id=vdagent,name=vdagent,clipboard=on \
    -device virtserialport,chardev=vdagent,name=com.redhat.spice.0 \
    -display spice-app
