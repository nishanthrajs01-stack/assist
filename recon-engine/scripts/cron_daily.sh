#!/bin/bash
# ReconEngine Daily Cron Runner
# Cron entry (2AM daily): 0 2 * * * /opt/recon-engine/scripts/cron_daily.sh >> /var/log/recon-engine.log 2>&1

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/venv"

echo "========================================"
echo " ReconEngine Daily Scan — $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "========================================"

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Change to project root
cd "$PROJECT_DIR"

# Run full scan across all programs with notifications
python main.py scan --all --notify

echo "========================================"
echo " Scan complete — $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "========================================"
