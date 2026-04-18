#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
app="$project_dir/.venv/bin/nordis-smb-inspector"

if [ ! -x "$app" ]; then
    echo "Kurulum bulunamadı. Önce ./setup.sh çalıştır." >&2
    exit 1
fi

exec "$app" "$@"
