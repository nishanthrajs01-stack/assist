#!/usr/bin/env python3
"""
webrecon.py — advanced parallel web reconnaissance combo for CTF challenges.

Features:
  - 2-second pre-flight TCP socket liveness check (fails fast on blackhole/unresponsive hosts)
  - Auto-insecure TLS flags for self-signed CTF certificates
  - Concurrent ThreadPoolExecutor running nmap, whatweb, gobuster/ffuf, and nikto in parallel

Usage:
    webrecon http://target:8080
    webrecon target.ctf:8000
    webrecon 10.10.10.10 --no-nikto
"""

import argparse
import concurrent.futures
import os
import re
import socket
import subprocess
import sys
from urllib.parse import urlparse

FLAG_PATTERNS = [
    r"[A-Za-z0-9_\-\.]{2,30}\{[^}]{1,120}\}",
    r"CTF\{[^}]{1,120}\}",
    r"flag\{[^}]{1,120}\}",
    r"(?:FLAG|flag|CTF|ctf)[_:\s=-]+([A-Za-z0-9_\-\.]{6,80})",
    r"[0-9]{2,4}[A-Za-z]{2,10}_[A-Za-z0-9_]{6,80}",
]

DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def run(cmd, timeout=30):
    """Run a shell command safely, handling non-UTF8 output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=timeout
        )
        out = (result.stdout or b"").decode("utf-8", errors="replace") + \
              (result.stderr or b"").decode("utf-8", errors="replace")
        return True, out.strip()
    except FileNotFoundError:
        return False, f"[skipped: '{cmd[0]}' not installed]"
    except subprocess.TimeoutExpired:
        return False, f"[skipped: '{cmd[0]}' timed out after {timeout}s]"
    except Exception as e:
        return False, f"[skipped: '{cmd[0]}' failed: {e}]"


def find_flags(text):
    hits = []
    for pat in FLAG_PATTERNS:
        matches = re.findall(pat, text)
        for m in matches:
            if isinstance(m, tuple):
                hits.extend([x for x in m if x])
            else:
                hits.append(m)
    return sorted(set(hits))


def resolve_wordlist(custom_path=None):
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for wl in DEFAULT_WORDLISTS:
        if os.path.isfile(wl):
            return wl
    return None


def parse_target(target_str):
    raw = target_str.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "http://" + raw

    parsed = urlparse(raw)
    host = parsed.hostname or "127.0.0.1"
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    base_url = f"{scheme}://{host}:{port}" if parsed.port else f"{scheme}://{host}"
    return base_url, host, port, scheme


def check_liveness(host, port, timeout=2.0):
    """Fast pre-flight socket probe to check if host/port is alive before launching tools."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "Host port reachable."
    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out (host down or port filtered)."
    except ConnectionRefusedError:
        return True, f"Host reachable (connection refused on port {port})."
    except Exception as e:
        return False, f"Cannot reach {host}:{port} ({e})."


def task_nmap(host, port, timeout):
    cmd = ["nmap", "-sV", "-p", str(port), "--open", "-T4", host]
    ok, out = run(cmd, timeout=timeout)
    return "nmap service scan", out


def task_whatweb(url, timeout):
    cmd = ["whatweb", "-a", "1", "--user-agent", "Mozilla/5.0", url]
    ok, out = run(cmd, timeout=timeout)
    return "whatweb fingerprint", out


def task_dir_enum(url, wordlist, timeout, is_https=False):
    if not wordlist:
        return "directory enumeration", "[skipped: no wordlist found]"
    
    gobuster_cmd = [
        "gobuster", "dir", "-u", url, "-w", wordlist,
        "-q", "--no-progress", "--no-error", "-t", "40"
    ]
    if is_https:
        gobuster_cmd.append("-k")
        
    ok, out = run(gobuster_cmd, timeout=timeout)
    if not ok or not out.strip():
        ffuf_cmd = [
            "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403", "-s", "-t", "40"
        ]
        if is_https:
            ffuf_cmd.append("-k")
        ok_ff, out_ff = run(ffuf_cmd, timeout=timeout)
        if ok_ff and out_ff.strip():
            out = out_ff
    return "directory enumeration", out or "(no paths discovered)"


def task_nikto(url, timeout, is_https=False):
    cmd = ["nikto", "-h", url, "-Tuning", "123b", "-maxtime", f"{timeout}s"]
    if is_https:
        cmd.append("-ssl")
    ok, out = run(cmd, timeout=timeout + 5)
    return "nikto audit", out


def main():
    parser = argparse.ArgumentParser(description="webrecon — Advanced Parallel CTF Web Reconnaissance.")
    parser.add_argument("target", help="Target URL or host (e.g. http://target:8080 or 10.10.10.10)")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist for directory enumeration", default=None)
    parser.add_argument("--no-nikto", action="store_true", help="Skip the nikto scan step")
    parser.add_argument("--no-dir", action="store_true", help="Skip directory enumeration")
    parser.add_argument("--timeout", type=int, default=20, help="Timeout per tool in seconds (default 20)")
    parser.add_argument("--skip-liveness", action="store_true", help="Skip initial 2s TCP liveness probe")
    args = parser.parse_args()

    url, host, port, scheme = parse_target(args.target)
    wordlist = resolve_wordlist(args.wordlist)
    is_https = (scheme == "https")

    print(f"=== Advanced Parallel Web Recon: {url} ===")
    print(f"Host: {host} | Port: {port} | Scheme: {scheme}\n")

    # 1. Fast Pre-flight Liveness Check
    if not args.skip_liveness:
        alive, reason = check_liveness(host, port, timeout=2.0)
        if not alive:
            print(f"[!] Target Unreachable: {reason}")
            print("[!] Aborting scan early to prevent blocking timeouts. Use --skip-liveness to force.")
            sys.exit(1)

    print("[*] Target is reachable. Launching parallel reconnaissance tasks...")

    sections = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        futures.append(executor.submit(task_nmap, host, port, args.timeout))
        futures.append(executor.submit(task_whatweb, url, args.timeout))
        if not args.no_dir:
            futures.append(executor.submit(task_dir_enum, url, wordlist, args.timeout, is_https))
        if not args.no_nikto:
            futures.append(executor.submit(task_nikto, url, args.timeout, is_https))

        for fut in concurrent.futures.as_completed(futures):
            name, output = fut.result()
            sections[name] = output

    ordered_keys = ["nmap service scan", "whatweb fingerprint", "directory enumeration", "nikto audit"]
    for k in ordered_keys:
        if k in sections:
            print(f"--- {k} ---")
            print(sections[k] or "(no output)")
            print()

    # Flag scan
    all_text = "\n".join(sections.values())
    flags = find_flags(all_text)

    print("--- Flag scan ---")
    if flags:
        for f in flags:
            print(f"  POSSIBLE FLAG: {f}")
    else:
        print("  no flag-pattern matches in tool output")
    print()

    # Save report
    report_dir = os.path.expanduser("~/ctf/web")
    os.makedirs(report_dir, exist_ok=True)
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{host}_{port}")
    report_path = os.path.join(report_dir, f"webrecon_{safe_host}.txt")

    with open(report_path, "w", encoding="utf-8", errors="replace") as rf:
        rf.write(f"=== Web Recon: {url} ===\n")
        rf.write(f"Host: {host} | Port: {port} | Scheme: {scheme}\n\n")
        for k in ordered_keys:
            if k in sections:
                rf.write(f"--- {k} ---\n{sections[k]}\n\n")
        rf.write("--- Flags found ---\n")
        if flags:
            for f in flags:
                rf.write(f"  {f}\n")
        else:
            rf.write("  none\n")

    print(f"Combined report saved to: {report_path}")


if __name__ == "__main__":
    main()
