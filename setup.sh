#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
venv_dir="$project_dir/.venv"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Hata: python3 bulunamadı." >&2
    exit 1
fi

if [ ! -x "$venv_dir/bin/python" ]; then
    python3 -m venv "$venv_dir"
fi

"$venv_dir/bin/python" -m pip install -e "$project_dir"

echo "Kurulum tamamlandı. Paneli ./run.sh ile başlatabilirsin."
