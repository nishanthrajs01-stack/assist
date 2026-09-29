#!/bin/bash
# ============================================================
#  ReconEngine — Smart Desktop Launcher
#  Single-click start: launches dashboard server if not
#  already running, then opens the browser automatically.
# ============================================================

PROJECT_DIR="/home/user/recon-engine"
VENV_PYTHON="$PROJECT_DIR/venv/bin/python"
DASHBOARD_URL="http://127.0.0.1:8080"
PORT=8080
LOG_FILE="/tmp/recon-engine-dashboard.log"
PID_FILE="/tmp/recon-engine-dashboard.pid"

# ---------------------
# Helper: notify on KDE
# ---------------------
notify() {
  if command -v notify-send &>/dev/null; then
    notify-send "ReconEngine" "$1" --icon="$PROJECT_DIR/recon-engine.png" -t 4000
  fi
}

# ---------------------
# Check if dashboard is already running
# ---------------------
is_running() {
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi
  # Also check if port is bound
  if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
    return 0
  fi
  return 1
}

# ---------------------
# Start the dashboard server
# ---------------------
start_dashboard() {
  notify "Starting ReconEngine Dashboard..."
  cd "$PROJECT_DIR" || exit 1

  # Initialize DB if it doesn't exist yet
  if [ ! -f "$PROJECT_DIR/data/recon.db" ]; then
    "$VENV_PYTHON" main.py init-db >> "$LOG_FILE" 2>&1
  fi

  # Launch uvicorn in background
  nohup "$VENV_PYTHON" -m uvicorn dashboard.app:app \
    --host 127.0.0.1 \
    --port $PORT \
    --log-level warning \
    >> "$LOG_FILE" 2>&1 &

  echo $! > "$PID_FILE"

  # Wait up to 6 seconds for the server to be ready
  for i in $(seq 1 12); do
    sleep 0.5
    if curl -s -o /dev/null "$DASHBOARD_URL"; then
      notify "Dashboard is ready!"
      return 0
    fi
  done

  notify "Dashboard started (may take a moment to load)"
}

# ---------------------
# Open browser
# ---------------------
open_browser() {
  if command -v xdg-open &>/dev/null; then
    xdg-open "$DASHBOARD_URL"
  elif command -v firefox &>/dev/null; then
    firefox "$DASHBOARD_URL" &
  elif command -v chromium-browser &>/dev/null; then
    chromium-browser "$DASHBOARD_URL" &
  elif command -v google-chrome &>/dev/null; then
    google-chrome "$DASHBOARD_URL" &
  fi
}

# ---------------------
# Main logic
# ---------------------
if is_running; then
  notify "Dashboard already running — opening browser"
  open_browser
else
  start_dashboard
  open_browser
fi
