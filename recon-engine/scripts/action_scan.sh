#!/bin/bash
# ReconEngine — Run Full Scan action script
cd /home/user/recon-engine
/home/user/recon-engine/venv/bin/python main.py scan --all --notify
notify-send "ReconEngine" "Scan complete! Check dashboard for new alerts." \
  --icon=/home/user/recon-engine/recon-engine.png -t 6000
