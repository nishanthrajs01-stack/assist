#!/usr/bin/env python3
"""
triage.py — advanced universal first-look tool for CTF challenge files.

Usage:
    triage <file>

Runs file / exiftool / binwalk / streaming strings against the target,
computes sliding-window chunk entropy + overall entropy, detects flag patterns
(including brace-less, custom CTF prefixes, and key-value formats),
prints a quick verdict, and saves everything to a report.
"""

import argparse
import math
import os
import re
import subprocess
import sys
from collections import Counter

FLAG_PATTERNS = [
    r"[A-Za-z0-9_\-\.]{2,30}\{[^}]{1,120}\}",
    r"CTF\{[^}]{1,120}\}",
    r"flag\{[^}]{1,120}\}",
    r"(?:FLAG|flag|CTF|ctf)[_:\s=-]+([A-Za-z0-9_\-\.]{6,80})",
    r"[0-9]{2,4}[A-Za-z]{2,10}_[A-Za-z0-9_]{6,80}",
]


def run(cmd, timeout=30):
    """Run a shell command safely, handling non-UTF8 binary outputs without raising."""
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
        return False, f"[skipped: '{cmd[0]}' timed out]"
    except Exception as e:
        return False, f"[skipped: '{cmd[0]}' failed: {e}]"


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def sliding_window_entropy(data, chunk_size=1024):
    """Computes min, avg, max entropy across sliding chunks to find hidden encrypted blocks."""
    if not data:
        return 0.0, 0.0, 0.0
    if len(data) <= chunk_size:
        e = shannon_entropy(data)
        return e, e, e
    
    entropies = []
    for i in range(0, len(data) - chunk_size + 1, chunk_size // 2):
        chunk = data[i:i + chunk_size]
        entropies.append(shannon_entropy(chunk))
    
    if not entropies:
        e = shannon_entropy(data)
        return e, e, e
    return min(entropies), sum(entropies) / len(entropies), max(entropies)


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


def extract_flags_from_binary(path, min_len=6):
    """Stream strings extraction directly into flag regex to avoid truncation limits."""
    hits = []
    try:
        proc = subprocess.Popen(["strings", "-n", str(min_len), path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in proc.stdout:
            decoded = line.decode("utf-8", errors="ignore")
            found = find_flags(decoded)
            if found:
                hits.extend(found)
        proc.kill()
    except Exception:
        pass
    return sorted(set(hits))


def build_verdict(file_type, binwalk_out, global_entropy, max_chunk_entropy, flags):
    notes = []
    ft = file_type.lower()

    if flags:
        notes.append("Flag-like string found directly in the file!")

    if "zip" in binwalk_out.lower() or "archive" in binwalk_out.lower():
        notes.append("Possible embedded archive — try `binwalk -e` or `sweep` to extract.")

    if max_chunk_entropy > 7.6:
        notes.append(f"Localized high entropy ({max_chunk_entropy:.2f} bits/byte) — detected encrypted or compressed sub-blocks.")
    elif global_entropy > 7.5:
        notes.append("Globally high entropy — likely fully encrypted, compressed, or packed data.")
    elif global_entropy < 3.0:
        notes.append("Low overall entropy — mostly repetitive or plain uncompressed data.")

    if "elf" in ft:
        notes.append("ELF binary — likely Reverse or Pwn category.")
    elif "pe32" in ft or "ms-dos" in ft:
        notes.append("Windows PE binary — likely Reverse category.")
    elif any(x in ft for x in ("image", "png", "jpeg", "gif", "bitmap")):
        notes.append("Image file — check stego (zsteg/steghide) and EXIF metadata.")
    elif "pcap" in ft or "capture" in ft:
        notes.append("Packet capture — Forensics category, inspect via `sweep` or Wireshark.")
    elif "zip" in ft or "archive" in ft or "compressed" in ft:
        notes.append("Archive file — inspect contents, check for password protection.")
    elif "ascii text" in ft or "text" in ft:
        notes.append("Plain text — check for encoding chains via `decode`.")

    if not notes:
        notes.append("No strong signal yet — inspect manually.")

    return notes


def main():
    parser = argparse.ArgumentParser(description="Universal CTF file triage tool.")
    parser.add_argument("file", help="Path to the challenge file")
    args = parser.parse_args()

    path = args.file
    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a file.")
        sys.exit(1)

    print(f"=== Triage: {path} ===\n")

    # 1. file
    ok_file, file_out = run(["file", path])
    print("--- file ---")
    print(file_out or "(no output)")
    print()

    # 2. exiftool (filter benign errors)
    ok_exif, exif_out = run(["exiftool", path])
    clean_exif = "\n".join([line for line in exif_out.splitlines() if not line.startswith("Error:")]) if exif_out else ""
    print("--- exiftool ---")
    print(clean_exif or "(no metadata or unsupported format)")
    print()

    # 3. binwalk
    ok_bw, bw_out = run(["binwalk", path])
    print("--- binwalk ---")
    print(bw_out or "(no output)")
    print()

    # 4. streaming flag search
    flags = extract_flags_from_binary(path)
    print("--- flag search ---")
    if flags:
        for f in flags:
            print(f"  POSSIBLE FLAG: {f}")
    else:
        print("  no flag-pattern matches in file strings")
    print()

    # 5. entropy (global and sliding window)
    with open(path, "rb") as fh:
        data = fh.read()
    g_entropy = shannon_entropy(data)
    min_e, avg_e, max_e = sliding_window_entropy(data)
    print("--- entropy ---")
    print(f"Global: {g_entropy:.3f} bits/byte | Block Min: {min_e:.3f} | Block Avg: {avg_e:.3f} | Block Max: {max_e:.3f}\n")

    # 6. verdict
    verdict = build_verdict(file_out, bw_out, g_entropy, max_e, flags)
    print("--- verdict ---")
    for v in verdict:
        print(f"  * {v}")
    print()

    # 7. save report
    report_dir = os.path.expanduser("~/ctf/misc")
    os.makedirs(report_dir, exist_ok=True)
    base = os.path.basename(path)
    report_path = os.path.join(report_dir, f"triage_{base}.txt")
    with open(report_path, "w", encoding="utf-8", errors="replace") as rf:
        rf.write(f"=== Triage: {path} ===\n\n")
        rf.write("--- file ---\n" + file_out + "\n\n")
        rf.write("--- exiftool ---\n" + clean_exif + "\n\n")
        rf.write("--- binwalk ---\n" + bw_out + "\n\n")
        rf.write("--- flags found ---\n" + ("\n".join(flags) if flags else "none") + "\n\n")
        rf.write(f"--- entropy ---\nGlobal: {g_entropy:.3f} bits/byte (Block Max: {max_e:.3f})\n\n")
        rf.write("--- verdict ---\n" + "\n".join(f"* {v}" for v in verdict) + "\n")

    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
