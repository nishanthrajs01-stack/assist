#!/usr/bin/env bash
# ==============================================================================
# CTF Automation Suite - Quick Startup & Interactive Launcher
# ==============================================================================

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Color definitions
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Ensure executable permissions on all Python scripts
chmod +x "$DIR"/*.py 2>/dev/null || true

# Setup symlinks into ~/.local/bin if not present
mkdir -p "$HOME/.local/bin"
for tool in triage sweep decode reverse webrecon; do
    if [ -f "$DIR/${tool}.py" ]; then
        ln -sf "$DIR/${tool}.py" "$HOME/.local/bin/$tool"
    fi
done

# Header
clear
echo -e "${CYAN}${BOLD}=================================================================${NC}"
echo -e "${GREEN}${BOLD}             CTF AUTOMATION SUITE v2.0 - LAUNCHER               ${NC}"
echo -e "${CYAN}${BOLD}=================================================================${NC}"
echo -e "${BLUE}Suite Directory:${NC} $DIR"
echo -e "${BLUE}PATH Tools:     ${NC} ~/.local/bin/{triage, sweep, decode, reverse, webrecon}"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"
echo ""

# Menu
echo -e "${BOLD}Select a tool or action to run:${NC}"
echo -e "  ${GREEN}[1]${NC} ${BOLD}triage.py${NC}      - Universal file triage & sliding-window entropy"
echo -e "  ${GREEN}[2]${NC} ${BOLD}sweep.py${NC}       - Forensics, multi-stream PCAP & Steghide carve"
echo -e "  ${GREEN}[3]${NC} ${BOLD}decode.py${NC}      - Multi-layer crypto & multi-byte XOR auto-decoder"
echo -e "  ${GREEN}[4]${NC} ${BOLD}reverse.py${NC}     - Sub-second Radare2 disassembler & Headless Ghidra"
echo -e "  ${GREEN}[5]${NC} ${BOLD}webrecon.py${NC}    - 4x Parallel web reconnaissance & endpoint fuzzing"
echo -e "  ${YELLOW}[6]${NC} ${BOLD}Reset Challenge${NC}- Re-initialize the 5-in-1 CTF challenge scenario"
echo -e "  ${MAGENTA}[7]${NC} ${BOLD}Launch Dashboard${NC}- Open the Web Command Center in browser"
echo -e "  ${CYAN}[8]${NC} ${BOLD}Run Test Suite${NC} - Execute self-test benchmark on all 5 tools"
echo -e "  ${RED}[0]${NC} Exit"
echo ""

read -rp "$(echo -e "${BOLD}Enter choice [0-8]: ${NC}")" choice

case "$choice" in
    1)
        echo ""
        echo -e "${CYAN}--- [1] triage.py ---${NC}"
        read -rp "Enter target file path (default: /home/user/Desktop/mystery.chall): " target
        target="${target:-/home/user/Desktop/mystery.chall}"
        "$DIR/triage.py" "$target"
        ;;
    2)
        echo ""
        echo -e "${CYAN}--- [2] sweep.py ---${NC}"
        read -rp "Enter evidence file path (default: /home/user/Desktop/mystery.chall): " target
        target="${target:-/home/user/Desktop/mystery.chall}"
        "$DIR/sweep.py" "$target"
        ;;
    3)
        echo ""
        echo -e "${CYAN}--- [3] decode.py ---${NC}"
        echo "Example: UEdTezVfZzAweTVfMV96NDVnM2VfcHU0MWFfcDB6Y3kzZzN9"
        read -rp "Enter string, hex, or payload: " payload
        payload="${payload:-UEdTezVfZzAweTVfMV96NDVnM2VfcHU0MWFfcDB6Y3kzZzN9}"
        read -rp "Search depth (default: 2): " depth
        depth="${depth:-2}"
        "$DIR/decode.py" "$payload" --depth "$depth"
        ;;
    4)
        echo ""
        echo -e "${CYAN}--- [4] reverse.py ---${NC}"
        read -rp "Enter binary path (default: /home/user/ctf/challenge/keychecker): " target
        target="${target:-/home/user/ctf/challenge/keychecker}"
        read -rp "Run deep Ghidra decompile? [y/N]: " ghidra_opt
        if [[ "$ghidra_opt" =~ ^[Yy]$ ]]; then
            "$DIR/reverse.py" "$target" --ghidra
        else
            "$DIR/reverse.py" "$target"
        fi
        ;;
    5)
        echo ""
        echo -e "${CYAN}--- [5] webrecon.py ---${NC}"
        read -rp "Enter target URL/Host (default: http://127.0.0.1:9191): " target
        target="${target:-http://127.0.0.1:9191}"
        read -rp "Skip nikto audit for speed? [Y/n]: " nikto_opt
        if [[ "$nikto_opt" =~ ^[Nn]$ ]]; then
            "$DIR/webrecon.py" "$target"
        else
            "$DIR/webrecon.py" "$target" --no-nikto
        fi
        ;;
    6)
        echo ""
        echo -e "${YELLOW}--- [6] Reset Challenge Environment ---${NC}"
        if [ -f "/home/user/ctf/challenge/setup_challenge.py" ]; then
            python3 "/home/user/ctf/challenge/setup_challenge.py"
        else
            echo "setup_challenge.py not found in /home/user/ctf/challenge/"
        fi
        ;;
    7)
        echo ""
        echo -e "${MAGENTA}--- [7] Launching Interactive Dashboard ---${NC}"
        if command -v xdg-open >/dev/null 2>&1; then
            xdg-open "$DIR/index.html" 2>/dev/null &
            echo "Opened $DIR/index.html in default browser."
        else
            echo "Open file://$DIR/index.html in your web browser."
        fi
        ;;
    8)
        echo ""
        echo -e "${CYAN}--- [8] Running Fast Benchmark Test Suite ---${NC}"
        python3 -c "
import subprocess, time

tests = [
    ('triage', ['$DIR/triage.py', '/home/user/Desktop/mystery.chall']),
    ('sweep', ['$DIR/sweep.py', '/home/user/Desktop/mystery.chall']),
    ('reverse', ['$DIR/reverse.py', '/home/user/ctf/challenge/keychecker']),
    ('decode', ['$DIR/decode.py', 'UEdTezVfZzAweTVfMV96NDVnM2VfcHU0MWFfcDB6Y3kzZzN9']),
]

for name, cmd in tests:
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True)
    dt = time.time() - t0
    status = 'PASS' if r.returncode == 0 else f'FAIL({r.returncode})'
    print(f'[{status}] {name:<10} in {dt:.2f}s')
"
        ;;
    0)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid selection.${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
