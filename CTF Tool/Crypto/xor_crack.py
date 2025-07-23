#!/usr/bin/env python3

import argparse
import sys
from pwn import xor
import string
import os

# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------

def read_ciphertext(args):
    if args.ciphertext:
        try:
            return bytes.fromhex(args.ciphertext.strip())
        except ValueError:
            sys.exit("[!] Invalid hex ciphertext.")
    elif args.cipherfile:
        try:
            with open(args.cipherfile, "rb") as f:
                return f.read()
        except Exception as e:
            sys.exit(f"[!] Failed to read file: {e}")
    else:
        sys.exit("[!] No ciphertext provided.")

def is_printable_ascii(b):
    return all(chr(c) in string.printable for c in b)

def english_score(s):
    freq_order = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    return sum([freq_order.find(chr(c).upper()) for c in s if chr(c).isalpha()])

def save_output(path, key, plaintext):
    with open(path, "w") as f:
        f.write(f"[+] Key (ASCII): {key.decode('latin1')}\n")
        f.write(f"[+] Key (HEX):   {key.hex()}\n\n")
        f.write("[+] Decrypted Message:\n")
        f.write(plaintext.decode('latin1', errors='replace'))
    print(f"[+] Output written to {path}")

def detect_repeating_key(partial, max_len=40):
    for l in range(1, min(len(partial), max_len) + 1):
        if partial[:len(partial)] == (partial[:l] * ((len(partial) // l) + 1))[:len(partial)]:
            return partial[:l]
    return partial

# ------------------------------
# CORE LOGIC
# ------------------------------

def crack_with_known(cipher, known, offset):
    if offset >= len(cipher):
        sys.exit("[!] Offset beyond ciphertext length.")
    partial_key = xor(cipher[offset:offset+len(known)], known)
    full_key = detect_repeating_key(partial_key)
    key_repeated = (full_key * ((len(cipher) // len(full_key)) + 1))[:len(cipher)]
    plaintext = xor(cipher, key_repeated)
    return full_key, plaintext

def brute_force_single_byte(cipher):
    results = []
    for k in range(256):
        p = xor(cipher, bytes([k]) * len(cipher))
        score = english_score(p)
        results.append((score, k, p))
    results.sort(reverse=True)
    best = results[0]
    print(f"\n[+] Brute XOR Top Results:")
    for score, k, p in results[:5]:
        try:
            print(f"[Key: {k:02x}] Score: {score:.2f}\n    {p.decode('utf-8', errors='replace')}\n")
        except Exception:
            continue
    return best[1], best[2]

# ------------------------------
# MAIN
# ------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="🔓 XOR Decryption Tool — Known Plaintext / Brute / Offset / File / Flag Detection",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  xor_crack.py -c <hex> -k crypto{
  xor_crack.py -c <hex> --brute
  xor_crack.py --cipherfile cipher.bin -k crypto{ --offset 12
  xor_crack.py -c <hex> -k VXON{ --check-flag-format VXON{"""
    )

    parser.add_argument("-c", "--ciphertext", help="Hex-encoded ciphertext")
    parser.add_argument("--cipherfile", help="File containing ciphertext")
    parser.add_argument("-k", "--known", help="Known plaintext (e.g., crypto{)")
    parser.add_argument("--offset", type=int, default=0, help="Offset in ciphertext to align known plaintext")
    parser.add_argument("--output", "-o", help="Write output to file")
    parser.add_argument("--brute", action="store_true", help="Brute force single-byte XOR")
    parser.add_argument("--check-flag-format", help="Check if decrypted output contains a flag prefix")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    cipher = read_ciphertext(args)

    if args.brute:
        key, plaintext = brute_force_single_byte(cipher)
        print(f"[+] Brute-force key: {hex(key)}")
    elif args.known:
        key, plaintext = crack_with_known(cipher, args.known.encode(), args.offset)
        print(f"[+] Key (ASCII): {key.decode('latin1', errors='replace')}")
        print(f"[+] Key (HEX):   {key.hex()}")
    else:
        sys.exit("[!] Use either --brute or provide -k known plaintext.")

    print("\n[+] Decrypted:")
    print(plaintext.decode('latin1', errors='replace'))

    if args.check_flag_format:
        if args.check_flag_format in plaintext.decode(errors='ignore'):
            print(f"[✓] Flag format matched: {args.check_flag_format}")
        else:
            print("[✗] Flag format not found.")

    if args.output:
        save_output(args.output, key if isinstance(key, bytes) else bytes([key]), plaintext)

if __name__ == "__main__":
    main()
