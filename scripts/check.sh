#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
project_python="$project_dir/.venv/bin/python"

if [ ! -x "$project_python" ]; then
    echo "Development environment not found. Run ./setup.sh first." >&2
    exit 1
fi

if ! "$project_python" -m ruff --version >/dev/null 2>&1; then
    echo "Development dependencies are missing." >&2
    echo ".venv/bin/pip install -e '.[dev]'" >&2
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "Node.js is required for the JavaScript syntax check." >&2
    exit 1
fi

cd "$project_dir"

"$project_python" -m ruff check .
"$project_python" -m pytest
"$project_python" -m compileall -q src tests scripts
node --check src/nordis_smb_inspector/web/static/app.js
sh -n setup.sh
sh -n run.sh
sh -n scripts/check.sh
sh -n scripts/setup-local-samba-lab.sh
bash -n scripts/prepare-windows-server-guest-tools.sh
bash -n scripts/run-windows-server-lab.sh

echo "All local checks passed."
