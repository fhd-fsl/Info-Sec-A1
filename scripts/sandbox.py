#!/usr/bin/env python3
"""
PsycoSupport affine-cipher interactive mapping sandbox.

Pure interactive mode: you assign cipher -> plaintext letter pairs by hand
for ONE direction at a time (C2S or S2C have different keys). Each session
prints only the colored ciphertext and the controls.

  - Unmapped cipher letters : RED (original letter).
  - Mapped cipher letters   : GREEN (plaintext letter).
  - Reassignment works: cipher c = q then c = i  ->  c now decrypts to i.

No frequency tables, no hints, no key solving, no decryption unless you type
the mapping. Reads only from ciphers.csv.
"""

import csv
import os

GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


def apply_mapping(text, mapping):
    """Unmapped cipher letters: original form in RED. Mapped: plaintext in GREEN."""
    out = []
    for ch in text:
        if ch.isalpha():
            pt = mapping.get(ch.lower())
            if pt is None:
                out.append(RED + ch + RESET)
            elif ch.isupper():
                out.append(GREEN + pt.upper() + RESET)
            else:
                out.append(GREEN + pt + RESET)
        else:
            out.append(ch)
    return "".join(out)


# Module-level handle so the loop can find matching ciphertexts.
_rows = []


def sandbox_direction(direction):
    """Interactive loop for a single direction."""
    mapping = {}
    if direction == "C2S":
        prompt = "C2S> "
    else:
        prompt = "S2C> "

    stream_rows = [r for r in _rows if r["direction"] == direction]
    concat = "".join(r["ciphertext"] for r in stream_rows)

    while True:
        print("\n" + "=" * 60)
        print(f"{direction} (client->server)" if direction == "C2S"
              else f"{direction} (server->client)")
        print("=" * 60)
        print("  mappings:", end="")
        if not mapping:
            print("  (none)")
        else:
            print("  " + ", ".join(f"{k}={v}" for k, v in sorted(mapping.items())))

        print("\n  Commands:")
        print(f"    <cipher>=<plain>   assign/reassign plaintext (e.g. c=e)")
        print("    show              list mappings")
        print("    clear             reset mappings for this direction")
        print("    back              return to direction menu")
        print("    quit / exit       quit")
        print()

        raw = input(prompt).strip()
        if not raw:
            continue
        cmd = raw.lower()
        if cmd in ("quit", "exit", "q"):
            return False
        if cmd == "back":
            return True
        if cmd == "show":
            if not mapping:
                print("  (no mappings assigned)")
            else:
                print("  current mappings:")
                for k in sorted(mapping):
                    print(f"    {k} -> {mapping[k]}")
            continue
        if cmd == "clear":
            mapping.clear()
            print("  cleared")
            continue
        if "=" not in raw:
            print("  usage: <cipher-letter>=<plaintext-letter>")
            continue
        lhs, rhs = raw.split("=", 1)
        lhs, rhs = lhs.strip().lower(), rhs.strip().lower()
        if len(lhs) != 1 or len(rhs) != 1 or not lhs.isalpha() or not rhs.isalpha():
            print("  both sides must be single letters")
            continue
        if lhs in mapping and mapping[lhs] != rhs:
            print(f"  overwrite: '{lhs}' was '{mapping[lhs]}', now '{rhs}'")
        mapping[lhs] = rhs
        print(f"  set: '{lhs}' -> '{rhs}'")

        print("\n  --- all sessions concatenated ---")
        print("  " + apply_mapping(concat, mapping))
        print("\n  --- per session ---")
        for r in stream_rows:
            print(f"    run {r['run']}: " + apply_mapping(r["ciphertext"], mapping))


def main():
    global _rows
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ciphers.csv")
    with open(csv_path, newline="") as f:
        _rows = list(csv.DictReader(f))

    while True:
        print("\n" + "=" * 40)
        print("PsycoSupport -- mapping sandbox")
        print("=" * 40)
        print("  1) C2S (client -> server)")
        print("  2) S2C (server -> client)")
        print("  0) quit / exit")
        choice = input("direction> ").strip().lower()

        if choice in ("quit", "exit", "q", "0"):
            print("done")
            break
        if choice == "1" or choice == "c2s":
            if sandbox_direction("C2S"):
                continue
            break
        if choice == "2" or choice == "s2c":
            if sandbox_direction("S2C"):
                continue
            break
        print("  pick 1, 2, or 0")


if __name__ == "__main__":
    main()
