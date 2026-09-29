#!/usr/bin/env python3
"""
sweep.py — advanced forensics sweep for CTF files.
Includes top-passphrase dictionary attack for Steghide and multi-stream PCAP analysis.

Usage:
    sweep <file>
"""

import argparse
import os
import re
import subprocess
import sys

FLAG_PATTERNS = [
    r"[A-Za-z0-9_\-\.]{2,30}\{[^}]{1,120}\}",
    r"CTF\{[^}]{1,120}\}",
    r"flag\{[^}]{1,120}\}",
    r"(?:FLAG|flag|CTF|ctf)[_:\s=-]+([A-Za-z0-9_\-\.]{6,80})",
    r"[0-9]{2,4}[A-Za-z]{2,10}_[A-Za-z0-9_]{6,80}",
]

TOP_STEGO_PASSWORDS = [
    "", "password", "admin", "secret", "123456", "stego", "root",
    "hackme", "hidden", "flag", "ctf", "pass", "qwerty", "letmein", "12345678"
]


def run(cmd, timeout=60):
    """Safely execute command, handling binary output without decoding crashes."""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
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


def detect_kind(path):
    ok, out = run(["file", "-b", path])
    ft = out.lower() if ok else ""
    if any(x in ft for x in ("pcap", "capture", "network")):
        return "pcap", out
    if any(x in ft for x in ("png", "jpeg", "jpg", "gif", "bitmap", "image", "tiff", "webp")):
        return "image", out
    if any(x in ft for x in ("zip", "archive", "compressed", "tar", "gzip", "rar", "7-zip")):
        return "archive", out
    if any(x in ft for x in ("elf", "pe32", "ms-dos executable")):
        return "binary", out
    return "unknown", out


def sweep_pcap(path, outdir):
    sections = {}

    # Check pcap validity first
    ok, count_out = run(["tshark", "-r", path, "-T", "fields", "-e", "frame.number"])
    packet_count = len(count_out.splitlines()) if ok and count_out else 0
    sections["PCAP Summary"] = f"Total packets analyzed: {packet_count}"

    # 1. HTTP object export
    http_dir = os.path.join(outdir, "http_objects")
    os.makedirs(http_dir, exist_ok=True)
    ok, http_objs = run(["tshark", "-r", path, "--export-objects", f"http,{http_dir}"])
    sections["HTTP object export"] = http_objs or "(no HTTP objects exported)"

    # 2. DNS queries
    ok, dns = run(["tshark", "-r", path, "-Y", "dns", "-T", "fields", "-e", "dns.qry.name"])
    sections["DNS queries"] = dns or "(no DNS queries)"

    # 3. Possible credentials and sensitive POST data
    ok, creds = run([
        "tshark", "-r", path, "-Y",
        "http.request.method==POST || ftp.request.command==USER || ftp.request.command==PASS || http.authorization",
        "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "http.authorization", "-e", "http.file_data",
    ])
    sections["Credentials / Auth / POST data"] = creds or "(no credentials captured)"

    # 4. Multi-stream TCP dump (follows top 5 TCP streams)
    tcp_streams_text = ""
    for stream_id in range(5):
        ok, stream_out = run(["tshark", "-r", path, "-q", "-z", f"follow,tcp,ascii,{stream_id}"])
        if ok and "Node 0:" in stream_out:
            tcp_streams_text += f"\n=== TCP Stream {stream_id} ===\n" + stream_out + "\n"
    sections["TCP Streams (Top 5)"] = tcp_streams_text or "(no active TCP streams found)"

    return sections


def sweep_image(path, outdir):
    sections = {}

    ok, zsteg_out = run(["zsteg", "-a", path])
    sections["zsteg (all methods)"] = zsteg_out

    # Quick dictionary attack on Steghide
    steg_results = []
    steg_out_file = f"{outdir}/steghide_out.txt"
    cracked = False
    for pwd in TOP_STEGO_PASSWORDS:
        ok, steg_out = run(["steghide", "extract", "-sf", path, "-xf", steg_out_file, "-p", pwd, "-f"])
        if ok and os.path.isfile(steg_out_file) and os.path.getsize(steg_out_file) > 0:
            steg_results.append(f"[SUCCESS] Steghide cracked with password: '{pwd}' -> extracted to steghide_out.txt")
            cracked = True
            break
    if not cracked:
        steg_results.append("[FAIL] Steghide extracted no data with top common passwords.")
    sections["steghide dictionary triage"] = "\n".join(steg_results)

    ok, exif_out = run(["exiftool", path])
    sections["exiftool"] = exif_out

    return sections


def sweep_archive_or_binary(path, outdir):
    sections = {}

    ok, bw_out = run(["binwalk", "-e", "--dd=.*", "-C", outdir, path])
    sections["binwalk -e (extract)"] = bw_out

    ok, fm_out = run(["foremost", "-i", path, "-o", f"{outdir}/foremost_out"])
    sections["foremost (carve)"] = fm_out

    return sections


def scan_dir_for_flags(outdir):
    hits = []
    for root, _, files in os.walk(outdir):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                with open(fp, "r", errors="ignore") as fh:
                    content = fh.read()
                found = find_flags(content)
                for f in found:
                    hits.append((fp, f))
            except Exception:
                continue
    return hits


def main():
    parser = argparse.ArgumentParser(description="Forensics sweep — branches by file type.")
    parser.add_argument("file", help="Path to the challenge file")
    args = parser.parse_args()

    path = args.file
    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a file.")
        sys.exit(1)

    kind, file_desc = detect_kind(path)
    print(f"=== Forensics sweep: {path} ===")
    print(f"file: {file_desc}")
    print(f"Detected kind: {kind}\n")

    base = os.path.splitext(os.path.basename(path))[0]
    outdir = os.path.expanduser(f"~/ctf/forensics/sweep_{base}")
    os.makedirs(outdir, exist_ok=True)

    sections = {}
    if kind == "pcap":
        print("Running pcap tools (tshark multi-stream)...")
        sections = sweep_pcap(path, outdir)
    elif kind == "image":
        print("Running image tools (zsteg, steghide dictionary, exiftool)...")
        sections = sweep_image(path, outdir)
    elif kind in ("archive", "binary"):
        print("Running archive/binary tools (binwalk -e, foremost)...")
        sections = sweep_archive_or_binary(path, outdir)
    else:
        print("Unknown file type — running generic tools (exiftool, binwalk -e).")
        ok, exif_out = run(["exiftool", path])
        sections["exiftool"] = exif_out
        ok, bw_out = run(["binwalk", "-e", "--dd=.*", "-C", outdir, path])
        sections["binwalk -e (extract)"] = bw_out

    all_text = ""
    for name, content in sections.items():
        print(f"--- {name} ---")
        preview = content[:1000] if content else "(no output)"
        print(preview)
        if len(content) > 1000:
            print(f"...[{len(content) - 1000} more chars, see report]")
        print()
        all_text += content + "\n"

    direct_flags = find_flags(all_text)
    try:
        with open(path, "r", errors="ignore") as fh:
            raw_content = fh.read()
        raw_flags = find_flags(raw_content)
    except Exception:
        raw_flags = []
    direct_flags = sorted(set(direct_flags) | set(raw_flags))

    extracted_flags = scan_dir_for_flags(outdir)

    print("--- Flag scan ---")
    if direct_flags:
        for f in direct_flags:
            print(f"  POSSIBLE FLAG (tool output / raw file): {f}")
    if extracted_flags:
        for fp, f in extracted_flags:
            print(f"  POSSIBLE FLAG (in {fp}): {f}")
    if not direct_flags and not extracted_flags:
        print("  none found yet — check extracted files manually in:", outdir)
    print()

    report_path = os.path.join(outdir, "sweep_report.txt")
    with open(report_path, "w", encoding="utf-8", errors="replace") as rf:
        rf.write(f"=== Forensics sweep: {path} ===\n")
        rf.write(f"file: {file_desc}\nDetected kind: {kind}\n\n")
        for name, content in sections.items():
            rf.write(f"--- {name} ---\n{content}\n\n")
        rf.write("--- Flags found ---\n")
        for f in direct_flags:
            rf.write(f"(tool output / raw file) {f}\n")
        for fp, f in extracted_flags:
            rf.write(f"({fp}) {f}\n")

    print(f"Extracted files + full report saved to: {outdir}")
    print(f"Report: {report_path}")


if __name__ == "__main__":
    main()
