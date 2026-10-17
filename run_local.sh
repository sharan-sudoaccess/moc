#!/usr/bin/env bash
# Local (non-Docker) launcher for Ubuntu.
#
#   ./run_local.sh setup       create .venv and install dependencies
#   ./run_local.sh api         start the FastAPI service      (http://127.0.0.1:8000)
#   ./run_local.sh dashboard   start the Streamlit dashboard  (http://127.0.0.1:8501)
#   ./run_local.sh all         start both (Ctrl+C stops both)
#   ./run_local.sh test        run the pytest suite
#   ./run_local.sh eval        run the evaluation script
#
# Settings are read from .env if it exists (copy .env.example to .env).
set -euo pipefail

cd "$(dirname "$0")"
VENV=".venv"
PY="$VENV/bin/python"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-8501}"

load_env() {
  if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
  fi
}

ensure_venv() {
  if [[ ! -x "$PY" ]]; then
    echo "Virtual environment not found. Run: ./run_local.sh setup" >&2
    exit 1
  fi
}

setup() {
  command -v python3 >/dev/null || { echo "python3 is required (sudo apt install python3 python3-venv)" >&2; exit 1; }
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
    || { echo "Python 3.10 or newer is required." >&2; exit 1; }
  if [[ ! -x "$PY" ]]; then
    python3 -m venv "$VENV" || { echo "venv creation failed. On Ubuntu: sudo apt install python3-venv" >&2; exit 1; }
  fi
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -r requirements-dev.txt
  [[ -f .env ]] || { cp .env.example .env; echo "Created .env from .env.example"; }
  mkdir -p logs
  echo "Setup complete."
}

run_api() {
  ensure_venv; load_env; mkdir -p logs
  exec "$VENV/bin/uvicorn" src.api:app --host "$API_HOST" --port "$API_PORT"
}

run_dashboard() {
  ensure_venv; load_env
  export API_URL="${API_URL:-http://$API_HOST:$API_PORT}"
  exec "$VENV/bin/streamlit" run app.py --server.port "$UI_PORT" --server.address 127.0.0.1
}

run_all() {
  ensure_venv; load_env; mkdir -p logs
  "$VENV/bin/uvicorn" src.api:app --host "$API_HOST" --port "$API_PORT" &
  API_PID=$!
  trap 'kill $API_PID 2>/dev/null || true' EXIT INT TERM
  for _ in $(seq 1 30); do
    curl -fs "http://$API_HOST:$API_PORT/health" >/dev/null 2>&1 && break
    sleep 0.5
  done
  echo "API running on http://$API_HOST:$API_PORT (docs: /docs)"
  export API_URL="${API_URL:-http://$API_HOST:$API_PORT}"
  "$VENV/bin/streamlit" run app.py --server.port "$UI_PORT" --server.address 127.0.0.1
}

case "${1:-}" in
  setup) setup ;;
  api) run_api ;;
  dashboard) run_dashboard ;;
  all) run_all ;;
  test) ensure_venv; "$PY" -m pytest "${@:2}" ;;
  eval) ensure_venv; load_env; "$PY" evaluation/evaluate.py "${@:2}" ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
