#!/bin/bash
# ReconEngine — Stop Dashboard action script
PID_FILE="/tmp/recon-engine-dashboard.pid"
if [ -f "$PID_FILE" ]; then
  pid=$(cat "$PID_FILE")
  kill "$pid" 2>/dev/null
  rm -f "$PID_FILE"
fi
# Also kill any remaining uvicorn on port 8080
fuser -k 8080/tcp 2>/dev/null || true
notify-send "ReconEngine" "Dashboard stopped." \
  --icon=/home/user/recon-engine/recon-engine.png -t 3000
