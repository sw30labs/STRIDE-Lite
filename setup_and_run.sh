#!/usr/bin/env bash
# One-shot setup + run: creates .venv, installs requirements, starts the GUI.
#
#   ./setup_and_run.sh          # install (if needed) + start the GUI
#   ./setup_and_run.sh install  # install only (venv + pip + .env check)
#   ./setup_and_run.sh gui      # start the GUI (no pip)
#   ./setup_and_run.sh model APP-123456 [--provider mlx|openai]
#   ./setup_and_run.sh scenario --json_file path/to/security_assessment.json [...]
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT"

GUI_HOST="${LG_HOST:-127.0.0.1}"
GUI_PORT="${LG_PORT:-8765}"

cmd_install() {
  if [[ ! -x .venv/bin/python ]]; then
    PY="${LG_PYTHON:-}"
    if [[ -z "$PY" ]]; then
      for c in python3.13 python3.12 python3.11 python3; do
        if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
      done
    fi
    if [[ -z "${PY:-}" ]]; then
      echo "error: no python3 found on PATH" >&2
      exit 1
    fi
    echo "==> Creating .venv with $PY ($("$PY" --version))"
    "$PY" -m venv .venv
  fi

  echo "==> Installing requirements"
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt

  if [[ ! -f .env ]]; then
    if [[ -f .env.example ]]; then
      cp .env.example .env
      echo "==> Created .env from .env.example — fill in your keys"
    else
      echo "==> No .env found. Copy .env.example and fill in your keys." >&2
    fi
  fi
}

cmd_gui() {
  echo "==> Starting GUI at http://${GUI_HOST}:${GUI_PORT}"
  exec .venv/bin/python src/python/gui.py --host "$GUI_HOST" --port "$GUI_PORT"
}

case "${1:-}" in
  install)
    cmd_install
    ;;
  gui|up)
    cmd_gui
    ;;
  model)
    shift
    exec .venv/bin/python src/python/model.py "$@"
    ;;
  scenario)
    shift
    exec .venv/bin/python src/python/scenario.py "$@"
    ;;
  "")
    cmd_install
    cmd_gui
    ;;
  -h|--help)
    sed -n '2,8p' "$0"
    ;;
  *)
    echo "unknown command ${1:-}" >&2
    sed -n '2,8p' "$0" >&2
    exit 1
    ;;
esac
