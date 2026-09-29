#!/usr/bin/env python3
"""
decode.py — advanced crypto auto-decoder for CTF blobs.

Usage:
    decode "SGVsbG8gV29ybGQh"
    decode -f blob.txt
    decode -f blob.txt --depth 3

Supports Base64, Base32, Base85, Hex, Binary, ROT1–25, URL decoding,
Single-Byte XOR, and Known-Prefix + Statistical Multi-Byte XOR cracking.
"""

import argparse
import base64
import binascii
import os
import re
import string
import sys
import urllib.parse

FLAG_PATTERNS = [
    r"[A-Za-z0-9_\-\.]{2,30}\{[A-Za-z0-9_\-\.\:\!\?]{2,120}\}",
    r"CTF\{[A-Za-z0-9_\-\.\:\!\?]{1,120}\}",
    r"flag\{[A-Za-z0-9_\-\.\:\!\?]{1,120}\}",
    r"(?:FLAG|flag|CTF|ctf)[_:\s=-]+([A-Za-z0-9_\-\.]{6,80})",
]

KNOWN_CTF_PREFIXES = [b"CTF{", b"flag{", b"FLAG{", b"ctf{"]

PRINTABLE = set(string.printable)
LETTER_FREQ = {
    'e': 12.02, 't': 9.10, 'a': 8.12, 'o': 7.68, 'i': 7.31, 'n': 6.95,
    's': 6.28, 'r': 6.02, 'h': 5.92, 'd': 4.32, 'l': 3.98, 'u': 2.88,
    'c': 2.71, 'm': 2.61, 'f': 2.30, 'y': 2.11, 'w': 2.09, 'g': 2.03,
    'p': 1.82, 'b': 1.49, 'v': 1.11, 'k': 0.69, 'x': 0.17, 'q': 0.11,
    'j': 0.10, 'z': 0.07, ' ': 15.0, '{': 5.0, '}': 5.0, '_': 5.0
}


def has_flag(text):
    hits = []
    # Avoid matching on strings with non-ASCII or non-alphanumeric braces
    for pat in FLAG_PATTERNS:
        matches = re.findall(pat, text)
        for m in matches:
            if isinstance(m, tuple):
                hits.extend([x for x in m if x and " " not in x])
            elif " " not in m:
                hits.append(m)
    return sorted(set(hits))


def printable_ratio(s):
    if not s:
        return 0.0
    return sum(1 for c in s if c in PRINTABLE) / len(s)


def try_decode_bytes(raw):
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return None


def attempt_base64(s):
    out = []
    candidate = s.strip()
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
        text = try_decode_bytes(raw)
        if text and printable_ratio(text) > 0.6:
            out.append(("base64", text))
    except Exception:
        pass
    return out


def attempt_base32(s):
    out = []
    candidate = s.strip().rstrip("=").upper()
    if len(candidate) >= 4 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in candidate):
        padded = candidate + "=" * (-len(candidate) % 8)
        try:
            raw = base64.b32decode(padded, casefold=True)
            text = try_decode_bytes(raw)
            if text and printable_ratio(text) > 0.6:
                out.append(("base32", text))
        except Exception:
            pass
    return out


def attempt_base85(s):
    out = []
    candidate = s.strip()
    try:
        raw = base64.b85decode(candidate)
        text = try_decode_bytes(raw)
        if text and printable_ratio(text) > 0.6:
            out.append(("base85", text))
    except Exception:
        pass
    try:
        raw = base64.a85decode(candidate)
        text = try_decode_bytes(raw)
        if text and printable_ratio(text) > 0.6:
            out.append(("ascii85", text))
    except Exception:
        pass
    return out


def attempt_url(s):
    out = []
    if "%" in s:
        try:
            decoded = urllib.parse.unquote(s)
            if decoded != s and printable_ratio(decoded) > 0.7:
                out.append(("url_decode", decoded))
        except Exception:
            pass
    return out


def attempt_hex(s):
    out = []
    cleaned = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(cleaned) >= 4 and len(cleaned) % 2 == 0:
        try:
            raw = binascii.unhexlify(cleaned)
            text = try_decode_bytes(raw)
            if text and printable_ratio(text) > 0.6:
                out.append(("hex", text))
        except Exception:
            pass
    return out


def attempt_rot(s):
    out = []
    for shift in range(1, 26):
        shifted = []
        for c in s:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                shifted.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                shifted.append(c)
        out.append((f"rot{shift}", "".join(shifted)))
    return out


def attempt_xor_single_byte(s):
    out = []
    try:
        raw = s.encode("latin-1")
    except Exception:
        return out
    for key in range(1, 256):
        try:
            result = bytes(b ^ key for b in raw)
            text = try_decode_bytes(result)
            if text and printable_ratio(text) > 0.85:
                out.append((f"xor-0x{key:02x}", text))
        except Exception:
            continue
    return out


def crack_multibyte_xor(raw_bytes, max_key_len=8):
    results = []
    if len(raw_bytes) < 4:
        return results

    # 1. Known-prefix key derivation (CTF{, flag{, FLAG{)
    for prefix in KNOWN_CTF_PREFIXES:
        for klen in range(2, min(max_key_len + 1, len(raw_bytes))):
            cand_key = bytes([raw_bytes[i] ^ prefix[i % len(prefix)] for i in range(klen)])
            dec = bytes(raw_bytes[j] ^ cand_key[j % klen] for j in range(len(raw_bytes)))
            text = try_decode_bytes(dec)
            if text and printable_ratio(text) > 0.9 and all(ord(c) >= 32 or c in '\n\r\t' for c in text):
                key_repr = cand_key.decode("latin-1", errors="replace")
                results.append((f"xor-prefix-len{klen}[{key_repr}]", text))

    # 2. Statistical frequency search
    for klen in range(2, min(max_key_len + 1, len(raw_bytes) // 2 + 1)):
        key_chars = []
        for i in range(klen):
            slice_bytes = raw_bytes[i::klen]
            best_score = -1e9
            best_byte = 0
            for b in range(256):
                dec_slice = [sb ^ b for sb in slice_bytes]
                sc = sum(LETTER_FREQ.get(chr(c).lower(), -5.0) if chr(c) in PRINTABLE else -30.0 for c in dec_slice)
                if sc > best_score:
                    best_score = sc
                    best_byte = b
            key_chars.append(best_byte)
        
        full_key = bytes(key_chars)
        decrypted = bytes(raw_bytes[j] ^ full_key[j % klen] for j in range(len(raw_bytes)))
        text = try_decode_bytes(decrypted)
        if text and printable_ratio(text) > 0.9 and all(ord(c) >= 32 or c in '\n\r\t' for c in text):
            key_repr = full_key.decode("latin-1", errors="replace")
            results.append((f"xor-keylen-{klen}[{key_repr}]", text))
    return results


def attempt_multibyte_xor(s):
    out = []
    try:
        raw = s.encode("latin-1")
        cracked = crack_multibyte_xor(raw)
        out.extend(cracked)
    except Exception:
        pass
    
    cleaned = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(cleaned) >= 8 and len(cleaned) % 2 == 0:
        try:
            raw_hex = binascii.unhexlify(cleaned)
            cracked_hex = crack_multibyte_xor(raw_hex)
            for m, t in cracked_hex:
                out.append((f"hex -> {m}", t))
        except Exception:
            pass
    return out


def attempt_binary(s):
    out = []
    cleaned = re.sub(r"[^01]", "", s)
    if len(cleaned) >= 8 and len(cleaned) % 8 == 0:
        try:
            raw = bytes(
                int(cleaned[i : i + 8], 2) for i in range(0, len(cleaned), 8)
            )
            text = try_decode_bytes(raw)
            if text and printable_ratio(text) > 0.6:
                out.append(("binary", text))
        except Exception:
            pass
    return out


ATTEMPTS = [
    attempt_base64, attempt_base32, attempt_base85, attempt_url,
    attempt_hex, attempt_binary, attempt_rot,
    attempt_xor_single_byte, attempt_multibyte_xor
]


def score(text):
    s = 0.0
    pr = printable_ratio(text)
    s += pr * 20
    if pr < 0.85:
        s -= 50
    
    # Check for unprintable escape chars and penalize heavily
    unprintable_count = sum(1 for c in text if c not in string.printable or ord(c) < 32 and c not in '\n\r\t')
    s -= unprintable_count * 20

    if has_flag(text):
        s += 200
    lowered = text.lower()
    for word in ("flag", "ctf", "the", "is", "key", "secret", "admin", "pass", "hello", "world"):
        if word in lowered:
            s += 8
    for c in lowered:
        s += LETTER_FREQ.get(c, 0.0) * 0.1
    return s


def explore(s, depth, max_depth, seen, results, chain):
    if depth > max_depth or s in seen:
        return
    seen.add(s)

    for attempt_fn in ATTEMPTS:
        try:
            candidates = attempt_fn(s)
        except Exception:
            candidates = []
        for method, text in candidates:
            if not text or text == s:
                continue
            new_chain = chain + [method]
            sc = score(text)
            if sc > 10.0 or has_flag(text):
                results.append((sc, " -> ".join(new_chain), text))
            if depth < max_depth and printable_ratio(text) > 0.85:
                explore(text, depth + 1, max_depth, seen, results, new_chain)


def main():
    parser = argparse.ArgumentParser(description="Advanced crypto auto-decoder for CTF blobs.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("text", nargs="?", help="Input string to decode")
    group.add_argument("-f", "--file", help="Read input from a file instead")
    parser.add_argument(
        "--depth", type=int, default=2, help="How many layers deep to chain (default 2)"
    )
    parser.add_argument(
        "--top", type=int, default=10, help="How many top candidates to show (default 10)"
    )
    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            print(f"Error: '{args.file}' not found.")
            sys.exit(1)
        with open(args.file, "r", errors="ignore") as fh:
            source = fh.read().strip()
    else:
        source = args.text.strip()

    print(f"=== Decoding (depth={args.depth}) ===")
    print(f"Input: {source[:100]}{'...' if len(source) > 100 else ''}\n")

    results = []
    seen = set()
    explore(source, 1, args.depth, seen, results, [])

    if not results:
        print("No decodings produced printable output. Try increasing --depth,")
        print("or the encoding may not be one of: base64/base32/base85/hex/binary/rot/XOR.")
        sys.exit(0)

    dedup = {}
    for sc, chain, text in results:
        key = (chain, text)
        if key not in dedup or sc > dedup[key]:
            dedup[key] = sc
    merged = [(sc, chain, text) for (chain, text), sc in dedup.items()]
    merged.sort(key=lambda x: x[0], reverse=True)

    top = merged[: args.top]

    print(f"--- Top {len(top)} candidates (of {len(merged)} total) ---\n")
    for sc, chain, text in top:
        flags = has_flag(text)
        flag_marker = f"  <-- POSSIBLE FLAG: {flags}" if flags else ""
        snippet = text[:150].replace("\n", "\\n")
        print(f"[{sc:6.1f}] {chain}: {snippet}{flag_marker}")

    report_dir = os.path.expanduser("~/ctf/crypto")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, "decode_report.txt")
    with open(report_path, "w", encoding="utf-8", errors="replace") as rf:
        rf.write(f"Input: {source}\n\n")
        for sc, chain, text in merged:
            rf.write(f"[{sc:.1f}] {chain}: {text}\n")

    print(f"\nFull report ({len(merged)} candidates) saved to: {report_path}")


if __name__ == "__main__":
    main()
