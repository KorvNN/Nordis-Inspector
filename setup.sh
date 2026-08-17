#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
venv_dir="$project_dir/.venv"
pip_cache_dir="$project_dir/.pip-cache"
state_file="$venv_dir/.nordis-setup-state"
log_file="$project_dir/.setup.log"
force_install=false

if [ -t 1 ] && [ -z "${NO_COLOR+x}" ]; then
    color_blue=$(printf '\033[1;34m')
    color_green=$(printf '\033[1;32m')
    color_yellow=$(printf '\033[1;33m')
    color_red=$(printf '\033[1;31m')
    color_bold=$(printf '\033[1m')
    color_reset=$(printf '\033[0m')
else
    color_blue=""
    color_green=""
    color_yellow=""
    color_red=""
    color_bold=""
    color_reset=""
fi

stage() {
    printf '\n%s[%s/4]%s %s%s%s\n' \
        "$color_blue" "$1" "$color_reset" "$color_bold" "$2" "$color_reset"
}

success() {
    printf '      %s✓%s %s\n' "$color_green" "$color_reset" "$1"
}

warning() {
    printf '      %s!%s %s\n' "$color_yellow" "$color_reset" "$1"
}

fail() {
    printf '\n%sHata:%s %s\n' "$color_red" "$color_reset" "$1" >&2
    if [ -s "$log_file" ]; then
        printf '%sTeknik ayrıntılar:%s %s\n' "$color_yellow" "$color_reset" "$log_file" >&2
    fi
    exit 1
}

case "${1-}" in
    "") ;;
    --force) force_install=true ;;
    *)
        echo "Kullanım: ./setup.sh [--force]" >&2
        exit 2
        ;;
esac

if ! : > "$log_file"; then
    echo "Hata: Kurulum günlük dosyası oluşturulamadı: $log_file" >&2
    exit 1
fi

printf '%sNordis Inspector kurulumu%s\n' "$color_bold" "$color_reset"
stage 1 "Python kontrol ediliyor"

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 bulunamadı. Python 3.12 veya daha yeni bir sürüm kurun."
fi

if ! python_version=$(python3 -c '
import sys

if sys.version_info < (3, 12):
    raise SystemExit(1)
print(".".join(map(str, sys.version_info[:3])))
' 2>>"$log_file"); then
    fail "Python 3.12 veya daha yeni bir sürüm gerekiyor."
fi
success "Python $python_version bulundu."

stage 2 "Sanal ortam hazırlanıyor"

if [ ! -x "$venv_dir/bin/python" ]; then
    if ! python3 -m venv "$venv_dir" >>"$log_file" 2>&1; then
        fail "Sanal ortam oluşturulamadı. Python venv desteğinin kurulu olduğunu kontrol edin."
    fi
    success "Yeni sanal ortam oluşturuldu."
else
    success "Mevcut sanal ortam kullanılacak."
fi

stage 3 "Bağımlılık durumu denetleniyor"

if ! dependency_state=$("$venv_dir/bin/python" -c '
import hashlib
import pathlib
import sys

pyproject = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(pyproject.read_bytes()).hexdigest()
print(f"{sys.version_info.major}.{sys.version_info.minor}:{digest}")
' "$project_dir/pyproject.toml" 2>>"$log_file"); then
    fail "Proje bağımlılık bilgisi okunamadı. pyproject.toml dosyasını kontrol edin."
fi

if [ "$force_install" = false ] && [ -x "$venv_dir/bin/nordis-smb-inspector" ] && [ -r "$state_file" ]; then
    installed_state=$(sed -n '1p' "$state_file")
    if [ "$installed_state" = "$dependency_state" ]; then
        success "Bağımlılıklar güncel; indirme gerekmiyor."
        stage 4 "Kurulum hazır"
        success "Paneli ./run.sh ile başlatabilirsin."
        exit 0
    fi
fi
warning "Kurulum veya güncelleme gerekiyor."

stage 4 "Bağımlılıklar kuruluyor"
warning "İlk kurulum Kerberos paketleri nedeniyle birkaç dakika sürebilir."

if ! mkdir -p "$pip_cache_dir" >>"$log_file" 2>&1; then
    fail "Pip önbellek dizini oluşturulamadı. Dizin izinlerini kontrol edin."
fi

if ! PIP_CACHE_DIR="$pip_cache_dir" "$venv_dir/bin/python" -m pip install \
    --quiet \
    --disable-pip-version-check \
    --prefer-binary \
    -e "$project_dir" >>"$log_file" 2>&1; then
    fail "Bağımlılıklar kurulamadı. İnternet bağlantısını ve sistem Kerberos paketlerini kontrol edin."
fi

state_tmp="$state_file.tmp"
if ! printf '%s\n' "$dependency_state" > "$state_tmp" || ! mv "$state_tmp" "$state_file"; then
    fail "Kurulum durumu kaydedilemedi. Sanal ortam dizininin izinlerini kontrol edin."
fi

success "Bağımlılıklar hazır."
printf '\n%sKurulum tamamlandı.%s Paneli ./run.sh ile başlatabilirsin.\n' \
    "$color_green" "$color_reset"
