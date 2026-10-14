#!/usr/bin/env python3
"""
PsycoSupport -- affine-decrypt helper for manual key verification.

This is NOT a key-recovery tool. You supply (a^{-1} mod 26) and b yourself
(the whole point of the lab: you worked them out by hand with Al-Kindi),
and this script merely applies the decryption formula to the captured
ciphertexts in ciphers.csv so you can confirm your key is right.

  formula:  P = a^{-1} * (C - b)  mod 26

Run from anywhere; reads its own directory's ciphers.csv.
"""

import csv
import os

MOD = 26


def decrypt_letter(ch, a_inv, b):
    if ch.isupper():
        return chr((a_inv * (ord(ch) - 65 - b)) % MOD + 65)
    if ch.islower():
        return chr((a_inv * (ord(ch) - 97 - b)) % MOD + 97)
    return ch


def affine_decrypt(text, a_inv, b):
    return "".join(decrypt_letter(ch, a_inv, b) for ch in text)


def pick(by_dir):
    print("Pick a direction:")
    for i, (d, _) in enumerate(by_dir, 1):
        print(f"  {i}) {d}")
    print(f"  {len(by_dir) + 1}) ALL directions")
    choice = input("choice> ").strip()
    idx = int(choice) if choice.isdigit() else 0
    if 1 <= idx <= len(by_dir):
        return [by_dir[idx - 1]]
    return by_dir


def prompt_key():
    print("\nAffine decryption key (manual entry):")
    print("  P = a^{-1} * (C - b)  mod 26")
    a_inv = int(input("  a^{-1} mod 26 = ").strip())
    b = int(input("  b            = ").strip())
    return a_inv, b


def show(direction, a_inv, b, stream):
    for r in stream:
        ct = r["ciphertext"]
        pt = affine_decrypt(ct, a_inv, b)
        print(f"\n--- {direction}  run {r['run']} ---")
        print(f"  ciphertext : {ct}")
        print(f"  formula    : P = {a_inv} * (C - {b}) mod 26")
        print(f"  plaintext  : {pt}")


def main():
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ciphers.csv")
    with open(csv_path, newline="") as f:
        rows = list(csv.DictReader(f))

    by_dir = []
    seen = []
    for r in rows:
        d = r["direction"]
        if d not in seen:
            seen.append(d)
    for d in seen:
        stream = [r for r in rows if r["direction"] == d]
        by_dir.append((d, stream))

    sel = pick(by_dir)
    a_inv, b = prompt_key()

    for d, stream in sel:
        show(d, a_inv, b, stream)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
