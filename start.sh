#!/usr/bin/env bash
# One command to set up and run the whole project on Ubuntu:
#
#   ./start.sh                 setup + tests + API + dashboard + open browser
#   ./start.sh --skip-tests    same, without running the test suite
#   ./start.sh --no-browser    same, without opening the browser
#
# Every run: checks Python, creates/repairs .venv, installs dependencies,
# creates .env if missing, runs the tests, stops old instances on ports
# 8000/8501, starts the API and the dashboard, waits until both respond,
# and opens the dashboard. Press Ctrl+C to stop both.
set -euo pipefail

cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"
VENV=".venv"
PY="$VENV/bin/python"
API_URL_LOCAL="http://127.0.0.1:8000"
UI_URL="http://127.0.0.1:8501"
RUN_TESTS=1
OPEN_BROWSER=1

for arg in "$@"; do
  case "$arg" in
    --skip-tests) RUN_TESTS=0 ;;
    --no-browser) OPEN_BROWSER=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg (use --help)" >&2; exit 1 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    ✔ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m    ✘ %s\033[0m\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 1. Python
step "1/7 Checking Python"
command -v python3 >/dev/null || fail "python3 not found. Install it: sudo apt install -y python3 python3-venv python3-pip"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || fail "Python 3.10 or newer is required (found $(python3 --version))."
if ! python3 -c 'import ensurepip' >/dev/null 2>&1; then
  echo "    python3-venv is missing; installing it (needs your sudo password)..."
  sudo apt-get update -qq && sudo apt-get install -y -qq python3-venv python3-pip \
    || fail "Could not install python3-venv. Run: sudo apt install -y python3-venv python3-pip"
fi
ok "$(python3 --version)"

# ---------------------------------------------------------- 2. Virtual env
step "2/7 Preparing virtual environment (.venv)"
if [[ -x "$PY" ]] && ! "$PY" -c 'import sys' >/dev/null 2>&1; then
  echo "    Existing .venv is broken; recreating it."
  rm -rf "$VENV"
fi
if [[ ! -x "$PY" ]]; then
  python3 -m venv "$VENV" || fail "Could not create .venv. Run: sudo apt install -y python3-venv"
  ok "created .venv"
else
  ok ".venv exists"
fi

# ----------------------------------------------------------- 3. Dependencies
step "3/7 Installing dependencies (fast when already installed)"
if "$PY" -m pip install -q --disable-pip-version-check -r requirements-dev.txt; then
  ok "dependencies installed"
elif "$PY" -c 'import fastapi, uvicorn, streamlit, pandas, plotly, requests, pytest' >/dev/null 2>&1; then
  echo "    pip could not reach the internet, but all packages are already installed; continuing."
else
  fail "Dependency installation failed. Check your internet connection and run ./start.sh again."
fi

# -------------------------------------------------------- 4. Configuration
step "4/7 Configuration"
if [[ ! -f .env ]]; then
  cp .env.example .env
  ok "created .env from .env.example"
else
  ok ".env exists"
fi
set -a
# shellcheck disable=SC1091
source .env
set +a
export API_URL="${API_URL:-$API_URL_LOCAL}"
mkdir -p logs

# ------------------------------------------------------------------ 5. Tests
step "5/7 Running tests"
if [[ "$RUN_TESTS" == 1 ]]; then
  if "$PY" -m pytest -q -p no:cacheprovider > logs/tests.log 2>&1; then
    ok "$(tail -n 1 logs/tests.log | tr -d '=')"
  else
    tail -n 30 logs/tests.log >&2
    fail "Some tests failed (full output: logs/tests.log). Fix them or run ./start.sh --skip-tests"
  fi
else
  ok "skipped (--skip-tests)"
fi

# ------------------------------------------------- 6. Free ports and start
step "6/7 Starting API and dashboard"
# Stop instances of THIS project left over from an earlier run (matched by the .venv path).
pkill -f "$VENV/bin/uvicorn src.api:app" 2>/dev/null || true
pkill -f "$VENV/bin/streamlit run app.py" 2>/dev/null || true
sleep 1
port_busy() { "$PY" -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1', $1))==0 else 1)"; }
port_busy 8000 && fail "Port 8000 is used by another program. Find it with: ss -ltnp | grep 8000"
port_busy 8501 && fail "Port 8501 is used by another program. Find it with: ss -ltnp | grep 8501"

API_PID=""; UI_PID=""
cleanup() {
  trap - INT TERM EXIT
  echo
  echo "Stopping..."
  [[ -n "$UI_PID" ]] && kill "$UI_PID" 2>/dev/null || true
  [[ -n "$API_PID" ]] && kill "$API_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  echo "Stopped API and dashboard."
}
on_interrupt() { cleanup; exit 0; }
trap on_interrupt INT TERM
trap cleanup EXIT

"$VENV/bin/uvicorn" src.api:app --host 127.0.0.1 --port 8000 > logs/api.log 2>&1 &
API_PID=$!
"$VENV/bin/streamlit" run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true \
  > logs/dashboard.log 2>&1 &
UI_PID=$!

wait_for() {  # url, seconds, pid, logfile, name
  local url="$1" secs="$2" pid="$3" log="$4" name="$5"
  for _ in $(seq 1 "$((secs * 2))"); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -n 25 "$log" >&2
      fail "$name stopped unexpectedly (see $log)"
    fi
    if "$PY" -c "import urllib.request,sys; urllib.request.urlopen('$url', timeout=2); sys.exit(0)" >/dev/null 2>&1; then
      ok "$name is running"
      return 0
    fi
    sleep 0.5
  done
  tail -n 25 "$log" >&2
  fail "$name did not start within ${secs}s (see $log)"
}
wait_for "$API_URL_LOCAL/health" 30 "$API_PID" logs/api.log "API"
wait_for "$UI_URL/_stcore/health" 60 "$UI_PID" logs/dashboard.log "Dashboard"

# ------------------------------------------------------------------ 7. Done
step "7/7 Ready"
cat <<EOF

    Dashboard  : $UI_URL          <- use this for the demo
    API status : $API_URL_LOCAL/
    API docs   : $API_URL_LOCAL/docs
    Logs       : $PROJECT_DIR/logs/api.log, logs/dashboard.log

    Press Ctrl+C to stop both.
EOF

if [[ "$OPEN_BROWSER" == 1 ]] && command -v xdg-open >/dev/null && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  xdg-open "$UI_URL" >/dev/null 2>&1 || true
fi

# Keep running until Ctrl+C or until one of the two processes exits.
while kill -0 "$API_PID" 2>/dev/null && kill -0 "$UI_PID" 2>/dev/null; do
  sleep 2
done
echo "One of the services stopped; see logs/api.log and logs/dashboard.log." >&2
exit 1
