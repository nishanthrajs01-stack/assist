#!/usr/bin/env python3
"""
setup_challenge.py
One-click challenge initializer & reset script.
Sets up the entire multi-stage 5-in-1 CTF challenge.
"""

import os
import subprocess
import zipfile
from scapy.all import Ether, IP, TCP, Raw, wrpcap

CHALLENGE_DIR = "/home/user/ctf/challenge"
DESKTOP_DIR = "/home/user/Desktop"
ENTRYPOINT_FILE = os.path.join(DESKTOP_DIR, "mystery.chall")
SERVER_SCRIPT = os.path.join(CHALLENGE_DIR, "challenge_server.py")

def main():
    print("=== Initializing 5-in-1 CTF Challenge ===")
    os.makedirs(CHALLENGE_DIR, exist_ok=True)

    # 1. Compile Keychecker Binary
    print("[*] 1/4 Compiling stage binary (keychecker)...")
    src_c = os.path.join(CHALLENGE_DIR, "keychecker.c")
    bin_out = os.path.join(CHALLENGE_DIR, "keychecker")
    subprocess.run(["gcc", "-o", bin_out, src_c, "-no-pie", "-fno-stack-protector"], check=True)
    os.chmod(bin_out, 0o755)

    # 2. Build Traffic Capture
    print("[*] 2/4 Generating network artifact (traffic.pcap)...")
    pcap_path = os.path.join(CHALLENGE_DIR, "traffic.pcap")
    flag_hint = "Q1RGezVfdG9vbHNfb25lX2ZsYWdfd2VsbF9kb25lfQ=="
    payload = (
        b"GET /vault HTTP/1.1\r\nHost: 10.10.10.99\r\nUser-Agent: CTF-Agent\r\n"
        b"Authorization: Bearer " + flag_hint.encode() + b"\r\n\r\n"
    )
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Hint: port=9191\r\n\r\nAccess granted. Next: decode the bearer token.\n"
    
    pkts = [
        Ether()/IP(src="10.10.10.1", dst="10.10.10.99")/TCP(sport=54321, dport=8080, flags="S", seq=100),
        Ether()/IP(src="10.10.10.99", dst="10.10.10.1")/TCP(sport=8080, dport=54321, flags="SA", seq=200, ack=101),
        Ether()/IP(src="10.10.10.1", dst="10.10.10.99")/TCP(sport=54321, dport=8080, flags="A", seq=101, ack=201),
        Ether()/IP(src="10.10.10.1", dst="10.10.10.99")/TCP(sport=54321, dport=8080, flags="PA", seq=101, ack=201)/Raw(load=payload),
        Ether()/IP(src="10.10.10.99", dst="10.10.10.1")/TCP(sport=8080, dport=54321, flags="PA", seq=201, ack=len(payload)+101)/Raw(load=resp)
    ]
    wrpcap(pcap_path, pkts)

    # 3. Create Desktop mystery.chall Entrypoint Carrier
    print("[*] 3/4 Bundling challenge artifact (mystery.chall)...")
    zip_tmp = "/tmp/embedded_payload.zip"
    with zipfile.ZipFile(zip_tmp, "w") as zf:
        zf.write(bin_out, arcname="keychecker")
        zf.write(pcap_path, arcname="traffic.pcap")
    
    with open(zip_tmp, "rb") as f:
        zip_data = f.read()

    header = (
        b"CTF_CARRIER_V1\x00\x00"
        b"TASK_DESC=Multi-Stage Challenge Artifact\x00"
        b"HINT=Use triage to inspect, then extract with sweep.\x00"
    )
    with open(ENTRYPOINT_FILE, "wb") as f:
        f.write(header + zip_data)

    # 4. Launch Challenge Web Daemon
    print("[*] 4/4 Starting background vault service on port 9191...")
    subprocess.run(["pkill", "-f", "challenge_server.py"], stderr=subprocess.DEVNULL)
    subprocess.Popen(["nohup", "python3", SERVER_SCRIPT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    print("\n[+] Setup complete!")
    print(f"[+] Entrypoint file: {ENTRYPOINT_FILE}")
    print("[+] Walkthrough file: /home/user/Desktop/CHALLENGE_WALKTHROUGH.md")

if __name__ == "__main__":
    main()
