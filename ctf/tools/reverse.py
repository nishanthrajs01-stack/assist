#!/usr/bin/env python3
"""
reverse.py — advanced reverse engineering quick-look for a CTF binary.

Provides instant fast-path analysis via checksec, strings, and radare2 disassembly
(with automatic entrypoint / __libc_start_main fallback for stripped binaries),
with optional deep headless Ghidra decompilation.

Usage:
    reverse <binary>
    reverse <binary> --ghidra        # trigger deep headless Ghidra decompile
    reverse <binary> --timeout 180   # override timeout
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

FLAG_PATTERNS = [
    r"[A-Za-z0-9_\-\.]{2,30}\{[^}]{1,120}\}",
    r"CTF\{[^}]{1,120}\}",
    r"flag\{[^}]{1,120}\}",
    r"(?:FLAG|flag|CTF|ctf)[_:\s=-]+([A-Za-z0-9_\-\.]{6,80})",
    r"[0-9]{2,4}[A-Za-z]{2,10}_[A-Za-z0-9_]{6,80}",
]

GHIDRA_SEARCH_PATHS = [
    "/opt/ghidra",
    "/usr/share/ghidra",
    "/usr/local/ghidra",
]


def run(cmd, timeout=30):
    """Safe runner handling binary / non-UTF8 strings."""
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


def get_r2_fast_analysis(binary_path):
    """Disassembly of main with intelligent entry0/fcn fallback for stripped binaries."""
    if not shutil.which("r2"):
        return False, "[r2 not installed]"
    
    # First attempt: standard main disassembly
    ok, out = run(["r2", "-qc", "aa; afl; pdf @ sym.main || pdf @ main", binary_path], timeout=15)
    if ok and "sub " in out and ("ret" in out or "call" in out):
        return True, out

    # Fallback for stripped binaries: disassemble entry0 and functions
    ok_fallback, out_fallback = run(["r2", "-qc", "aa; ie; pdf @ entry0; afl", binary_path], timeout=15)
    return ok_fallback, out_fallback or out


def find_analyze_headless():
    found = shutil.which("analyzeHeadless")
    if found:
        return found
    for base in GHIDRA_SEARCH_PATHS:
        if not os.path.isdir(base):
            continue
        for root, _, files in os.walk(base):
            if "analyzeHeadless" in files:
                return os.path.join(root, "analyzeHeadless")
    return None


def run_ghidra_decompile(binary_path, timeout, script_dir):
    analyze_headless = find_analyze_headless()
    if not analyze_headless:
        return False, "[skipped: analyzeHeadless not found — is Ghidra installed?]"

    with tempfile.TemporaryDirectory() as project_dir, tempfile.NamedTemporaryFile(
        suffix=".txt", delete=False
    ) as out_tmp:
        out_path = out_tmp.name

    cmd = [
        analyze_headless,
        project_dir,
        "ReverseQuickLook",
        "-import", binary_path,
        "-postScript", "decompile_dump.py", out_path,
        "-scriptPath", script_dir,
        "-deleteProject",
    ]
    ok, out = run(cmd, timeout=timeout)

    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                decompiled = f.read()
        except Exception:
            decompiled = ""
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass
        if decompiled.strip():
            return True, decompiled
    return False, out or "[no decompile output produced]"


def build_verdict(checksec_out):
    notes = []
    cs = checksec_out.lower()

    if "canary found" in cs and "no canary" not in cs:
        notes.append("Stack canary present — stack buffer overflow to ret address requires leak.")
    elif "no canary" in cs:
        notes.append("No stack canary — stack buffer overflow may be viable directly.")

    if "nx enabled" in cs:
        notes.append("NX enabled — shellcode on stack won't execute; look at ROP / ret2libc / GOT overwrite.")
    elif "nx disabled" in cs:
        notes.append("NX disabled — executable stack; shellcode injection is viable.")

    if "pie enabled" in cs:
        notes.append("PIE enabled — code addresses randomized; memory address leak required.")
    elif "no pie" in cs or "pie disabled" in cs:
        notes.append("No PIE — code addresses are static, fixed gadget offsets available.")

    return notes or ["No strong mitigation signal — inspect manually."]


def main():
    parser = argparse.ArgumentParser(description="Reverse engineering quick-look for a CTF binary.")
    parser.add_argument("binary", help="Path to the binary")
    parser.add_argument("--ghidra", action="store_true", help="Launch deep headless Ghidra decompilation")
    parser.add_argument("--timeout", type=int, default=120, help="Ghidra timeout in seconds (default 120)")
    args = parser.parse_args()

    path = args.binary
    if not os.path.isfile(path):
        print(f"Error: '{path}' is not a file.")
        sys.exit(1)

    print(f"=== Reverse quick-look: {path} ===\n")

    # 1. file
    ok_file, file_out = run(["file", path])
    print("--- file ---")
    print(file_out or "(no output)")
    print()

    # 2. checksec
    ok_cs, checksec_out = run(["checksec", f"--file={path}"])
    print("--- checksec ---")
    print(checksec_out or "(no output)")
    print()

    # 3. strings
    ok_str, strings_out_raw = run(["strings", "-n", "8", path])
    flags = find_flags(strings_out_raw)
    print("--- strings -n8 (flag search) ---")
    if flags:
        for f in flags:
            print(f"  POSSIBLE FLAG: {f}")
    else:
        print("  no flag-pattern matches in strings output")
    print()

    # 4. Fast-path radare2 disassembly preview with stripped fallback
    print("--- Fast-path radare2 disassembly ---")
    ok_r2, r2_out = get_r2_fast_analysis(path)
    print(r2_out[:1200] if ok_r2 else "[radare2 preview unavailable]")
    print()

    # 5. Optional Ghidra deep decompile
    decompiled_text = "(skipped — pass --ghidra to run headless Ghidra)"
    if args.ghidra:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        print(f"--- Ghidra headless decompile (timeout={args.timeout}s) ---")
        ok_gh, decompiled_text = run_ghidra_decompile(path, args.timeout, script_dir)
        print(decompiled_text[:1500])
        print()

    # 6. verdict
    verdict = build_verdict(checksec_out)
    print("--- verdict ---")
    for v in verdict:
        print(f"  * {v}")
    print()

    # 7. save report
    report_dir = os.path.expanduser("~/ctf/rev")
    os.makedirs(report_dir, exist_ok=True)
    base = os.path.basename(path)
    report_path = os.path.join(report_dir, f"reverse_{base}.txt")
    with open(report_path, "w", encoding="utf-8", errors="replace") as rf:
        rf.write(f"=== Reverse quick-look: {path} ===\n\n")
        rf.write("--- file ---\n" + file_out + "\n\n")
        rf.write("--- checksec ---\n" + checksec_out + "\n\n")
        rf.write("--- flags found in strings ---\n" + ("\n".join(flags) if flags else "none") + "\n\n")
        rf.write("--- radare2 fast-path ---\n" + (r2_out or "") + "\n\n")
        rf.write("--- Ghidra decompile ---\n" + decompiled_text + "\n\n")
        rf.write("--- verdict ---\n" + "\n".join(f"* {v}" for v in verdict) + "\n")

    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
