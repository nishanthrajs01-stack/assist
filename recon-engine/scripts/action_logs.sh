#!/bin/bash
# ReconEngine — Open Logs action script
LOG_FILE="/tmp/recon-engine-dashboard.log"
if command -v konsole &>/dev/null; then
  konsole --title "ReconEngine — Dashboard Logs" -e tail -f "$LOG_FILE"
elif command -v xterm &>/dev/null; then
  xterm -title "ReconEngine Logs" -bg "#0f0f1a" -fg "#a78bfa" -e tail -f "$LOG_FILE"
elif command -v gnome-terminal &>/dev/null; then
  gnome-terminal --title="ReconEngine Logs" -- tail -f "$LOG_FILE"
fi
