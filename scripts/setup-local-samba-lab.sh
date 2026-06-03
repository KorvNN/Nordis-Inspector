#!/bin/sh
set -eu

managed_marker="# Managed by Nordis SMB Inspector local lab"
config_path="/etc/samba/smb.conf"
lab_root="/srv/nordis-smb-lab"
lab_user="nordislab"
lab_password="Password123!"
lab_interfaces=${NORDIS_LAB_INTERFACES:-lo}
lab_hosts_allow=${NORDIS_LAB_HOSTS_ALLOW:-127.0.0.1 ::1}
lab_target=${NORDIS_LAB_TARGET:-127.0.0.1}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_python="$script_dir/../.venv/bin/python"

if [ "$(id -u)" -ne 0 ]; then
    echo "Bu betik sudo ile çalıştırılmalı." >&2
    exit 1
fi

if [ ! -x "$project_python" ]; then
    echo "Önce repo kökünde ./setup.sh çalıştırılmalı." >&2
    exit 1
fi

if [ -f "$config_path" ] && ! grep -Fqx "$managed_marker" "$config_path"; then
    echo "Mevcut /etc/samba/smb.conf Nordis lab tarafından yönetilmiyor." >&2
    echo "Güvenlik için dosyanın üzerine yazılmadı." >&2
    exit 1
fi

pacman -S --needed --noconfirm samba smbclient

if ! getent passwd "$lab_user" >/dev/null; then
    useradd --system --no-create-home --shell /usr/bin/nologin "$lab_user"
fi
lab_group=$(id -gn "$lab_user")

install -d -m 0750 -o "$lab_user" -g "$lab_group" "$lab_root/public"
install -d -m 0750 -o root -g root "$lab_root/finance"
install -d -m 0750 -o "$lab_user" -g "$lab_group" \
    "$lab_root/public/level-1" \
    "$lab_root/public/level-1/level-2" \
    "$lab_root/public/level-1/level-2/level-3"

lab_tmp=$(mktemp -d /tmp/nordis-smb-lab.XXXXXX)
cleanup() {
    rm -f \
        "$lab_tmp/smb.conf" \
        "$lab_tmp/readable-match.txt" \
        "$lab_tmp/offline-hash-sample.txt" \
        "$lab_tmp/readable-no-match.txt" \
        "$lab_tmp/deep-secret.txt" \
        "$lab_tmp/large-stream.txt" \
        "$lab_tmp/unreadable-secret.txt"
    rm -f \
        "$lab_tmp/office-secret.docx" \
        "$lab_tmp/spreadsheet-secret.xlsx" \
        "$lab_tmp/slides-secret.pptx" \
        "$lab_tmp/pdf-secret.pdf" \
        "$lab_tmp/archive-secrets.zip"
    rmdir "$lab_tmp" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

printf '%s\n' \
    "$managed_marker" \
    "[global]" \
    "    workgroup = WORKGROUP" \
    "    server role = standalone server" \
    "    security = user" \
    "    passdb backend = tdbsam" \
    "    interfaces = $lab_interfaces" \
    "    bind interfaces only = yes" \
    "    hosts allow = $lab_hosts_allow" \
    "    smb ports = 445" \
    "    server min protocol = SMB2_02" \
    "    server signing = mandatory" \
    "    map to guest = never" \
    "    load printers = no" \
    "    disable spoolss = yes" \
    "    printcap name = /dev/null" \
    "    log level = 0" \
    "    log file = /dev/null" \
    "" \
    "[Public]" \
    "    path = $lab_root/public" \
    "    browseable = yes" \
    "    read only = yes" \
    "    guest ok = no" \
    "    valid users = $lab_user" \
    "    follow symlinks = no" \
    "    wide links = no" \
    "" \
    "[Finance]" \
    "    path = $lab_root/finance" \
    "    browseable = yes" \
    "    read only = yes" \
    "    guest ok = no" \
    "    invalid users = $lab_user" \
    > "$lab_tmp/smb.conf"

printf '%s\n' \
    "ordinary laboratory line" \
    "password = NORDIS_LAB_CANARY_ONE" \
    "ordinary second line" \
    "PASSWORD = NORDIS_LAB_CANARY_TWO" \
    "api_key = NORDIS_TEST_CANARY" \
    > "$lab_tmp/readable-match.txt"

printf '%s\n' \
    "ordinary laboratory text" \
    "this file intentionally has no selected term" \
    > "$lab_tmp/readable-no-match.txt"

printf '%s\n' \
    "NTLM: 8846f7eaee8fb117ad06bdd830b7586c" \
    > "$lab_tmp/offline-hash-sample.txt"

printf '%s\n' \
    "client_secret = NORDIS_DEEP_CANARY" \
    > "$lab_tmp/deep-secret.txt"

awk 'BEGIN { for (i = 0; i < 131072; i++) print "ordinary streamed laboratory line" }' \
    > "$lab_tmp/large-stream.txt"
printf '%s\n' "password = NORDIS_LAB_STREAM_CANARY" >> "$lab_tmp/large-stream.txt"
printf '%s\n' "password = NORDIS_UNREADABLE_CANARY" > "$lab_tmp/unreadable-secret.txt"
"$project_python" "$script_dir/generate-lab-documents.py" "$lab_tmp"

install -m 0640 -o "$lab_user" -g "$lab_group" \
    "$lab_tmp/readable-match.txt" "$lab_root/public/readable-match.txt"
install -m 0640 -o "$lab_user" -g "$lab_group" \
    "$lab_tmp/readable-no-match.txt" "$lab_root/public/readable-no-match.txt"
install -m 0640 -o "$lab_user" -g "$lab_group" \
    "$lab_tmp/offline-hash-sample.txt" "$lab_root/public/offline-hash-sample.txt"
install -m 0640 -o "$lab_user" -g "$lab_group" \
    "$lab_tmp/deep-secret.txt" \
    "$lab_root/public/level-1/level-2/level-3/deep-secret.txt"
install -m 0640 -o "$lab_user" -g "$lab_group" \
    "$lab_tmp/large-stream.txt" "$lab_root/public/large-stream.txt"
install -m 000 -o root -g root \
    "$lab_tmp/unreadable-secret.txt" "$lab_root/public/unreadable-secret.txt"
install -m 0640 -o "$lab_user" -g "$lab_group" \
    "$lab_tmp/office-secret.docx" \
    "$lab_tmp/spreadsheet-secret.xlsx" \
    "$lab_tmp/slides-secret.pptx" \
    "$lab_tmp/pdf-secret.pdf" \
    "$lab_tmp/archive-secrets.zip" \
    "$lab_root/public/"
install -m 0644 -o root -g root "$lab_tmp/smb.conf" "$config_path"

printf '%s\n%s\n' "$lab_password" "$lab_password" | smbpasswd -s -a "$lab_user"
testparm -s "$config_path" >/dev/null
systemctl enable --now smb.service
systemctl restart smb.service

echo
echo "Nordis yerel Samba laboratuvarı hazır."
echo "Hedef: $lab_target"
echo "Domain: WORKGROUP"
echo "Kullanıcı: $lab_user"
echo "Parola: $lab_password"
echo "Share'ler: Public (okunabilir), Finance (erişim reddi)"
echo "Hash örneği: Public/offline-hash-sample.txt (NTLM parola: password)"
