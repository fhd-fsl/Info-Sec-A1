#!/usr/bin/env python3
"""
PsycoSupport -- local support client.

Interactively collects a username, mood (1-10), and a free-text concern,
then:
  1. Encrypts a composite payload (username|mood|concERN) using the
     Client->Server affine key.
  2. POSTs it to the local server at http://127.0.0.1:5000/message.
  3. Decrypts the returned Server->Client suggestion.
  4. Echoes the exact ciphertexts it produced/consumed, labelling them so
     they can be harvested for capture (console + Wireshark).

All shared constants (affine keys, endpoints) live in config.py. Edit config.py
to switch the running key pair; then restart both processes.
"""

import json
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# SHARED CONFIG (keys, endpoints) -- imported from config.py
# ---------------------------------------------------------------------------

from config import C2S_A, C2S_B, S2C_A, S2C_B, SERVER_URL, OLLAMA_TIMEOUT

# ---------------------------------------------------------------------------
# Affine cipher helpers (same definition as server.py)
# ---------------------------------------------------------------------------

MOD = 26


def modinv(a: int, m: int = MOD) -> int:
    """Return x such that (a*x) % m == 1 (raises if no inverse exists)."""
    if a % m == 0:
        raise ValueError(f"no modular inverse for a={a} mod {m}")
    # extended Euclidean algorithm
    x0, x1, b0, b1 = 1, 0, a, m
    while b1 != 0:
        q = b0 // b1
        b0, b1 = b1, b0 - q * b1
        x0, x1 = x1, x0 - q * x1
    if b0 != 1:
        raise ValueError(f"no modular inverse for a={a} mod {m}")
    return x0 % m


def _encrypt_letter(letter: str, a: int, b: int) -> str:
    if letter.isupper():
        return chr((a * (ord(letter) - 65) + b) % MOD + 65)
    if letter.islower():
        return chr((a * (ord(letter) - 97) + b) % MOD + 97)
    return letter


def affine_encrypt(plaintext: str, a: int, b: int) -> str:
    return "".join(_encrypt_letter(ch, a, b) for ch in plaintext)


def _decrypt_letter(letter: str, a: int, b: int) -> str:
    inv_a = modinv(a)
    if letter.isupper():
        return chr(inv_a * (ord(letter) - 65 - b) % MOD + 65)
    if letter.islower():
        return chr(inv_a * (ord(letter) - 97 - b) % MOD + 97)
    return letter


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    return "".join(_decrypt_letter(ch, a, b) for ch in ciphertext)


# ---------------------------------------------------------------------------
# User interaction
# ---------------------------------------------------------------------------

def read_nonempty(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value


def read_mood() -> int:
    while True:
        raw = input("Enter mood (1-10): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 10:
            return int(raw)
        print("  please enter an integer between 1 and 10.")


# ---------------------------------------------------------------------------
# Network / main flow
# ---------------------------------------------------------------------------

def send_message(payload: dict, timeout: int = OLLAMA_TIMEOUT) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        SERVER_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def main() -> None:
    print("=== PsycoSupport -- client ===")
    print(f"sending to {SERVER_URL}")

    username = read_nonempty("Enter username: ")
    mood = read_mood()
    concern = read_nonempty("Enter your concern: ")

    # Composite plaintext the server will decrypt into per-field values.
    plaintext = f"{username}|{mood}|{concern}"

    c2s_ciphertext = affine_encrypt(plaintext, C2S_A, C2S_B)

    # Echo the label so the capture is unambiguous.
    print()
    print("CIPHERTEXT_C2S:", c2s_ciphertext)

    try:
        # Send ONLY the ciphertext as the request body
        response = send_message({"ciphertext": c2s_ciphertext})
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(
            f"server returned HTTP {exc.code}: {body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"cannot reach server at {SERVER_URL}: {exc}\n"
            "is the server running? start with: python scripts/server.py"
        ) from exc

    if "error" in response:
        raise SystemExit(f"server error: {response['error']}")

    s2c_ciphertext = response.get("reply", "")

    print("CIPHERTEXT_S2C:", s2c_ciphertext)

    try:
        suggestion = affine_decrypt(s2c_ciphertext, S2C_A, S2C_B)
    except ValueError as exc:
        raise SystemExit(f"decrypt of server reply failed: {exc}")

    print()
    print("=== decrypted suggestion ===")
    print(suggestion)

    # Re-echo the ciphertexts at the end too, so a copy/paste of the console
    # gives a clean capture artifact.
    print()
    print("=== capture summary ===")
    print("username:", username)
    print("mood:", mood)
    print("C2S plaintext:", plaintext)
    print("CIPHERTEXT_C2S:", c2s_ciphertext)
    print("CIPHERTEXT_S2C:", s2c_ciphertext)


if __name__ == "__main__":
    main()
