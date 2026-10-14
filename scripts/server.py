#!/usr/bin/env python3
"""
PsycoSupport -- local support server.

A single-threaded HTTP server that:
  1. Receives encrypted client messages on 127.0.0.1:5000 (POST /message)
  2. Decrypts them with the Client->Server affine key
  3. Asks a local Ollama instance for a supportive suggestion
  4. Re-encrypts the suggestion with the Server->Client affine key
  5. Returns the result to the client

All shared constants (affine keys, endpoints, Ollama model) live in config.py.
Edit config.py to switch the running key pair; then restart both processes.
"""

import json
import sys
import socket
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# SHARED CONFIG (keys, endpoints, Ollama model)
# ---------------------------------------------------------------------------

from config import (
    C2S_A, C2S_B, S2C_A, S2C_B, SERVER_HOST, SERVER_PORT, SERVER_URL,
    OLLAMA_URL, OLLAMA_MODEL, OLLAMA_RETRIES, OLLAMA_TIMEOUT,
)

# ---------------------------------------------------------------------------
# Affine cipher helpers
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
    return letter  # non-letters pass through unchanged


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
# LLM request helpers
# ---------------------------------------------------------------------------

# The prompt is deliberately constrained so the model's output is short,
# structured, and contains fixed boilerplate. That structural regularity is
# exactly what makes a classical frequency analysis feasible later.
SYSTEM_PROMPT = (
    "You are a supportive psychologist. "
    "Give a short advice to the user based on their mood and concern. " \
    "Do not write more than 15 words."
)


class _OllamaHTTPError(Exception):
    """Raised when a call to the Ollama API fails after retries."""


def ollama_generate(prompt: str, retries: int = 3, timeout: int = 180) -> str:
    """Ask local Ollama for a non-streaming completion with backoff retries."""
    last = None
    for attempt in range(retries):
        try:
            body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode()
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/generate",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode())
            answer = payload.get("response", "").strip()
            if answer:
                return answer
            last = "empty response"
        except (TimeoutError, socket.timeout, urllib.error.URLError) as exc:
            last = exc
        time.sleep(2.0 * (attempt + 1))
    raise _OllamaHTTPError(f"Ollama unavailable after {retries} attempts: {last}")


def build_prompt(username: str, mood: int, concern: str) -> str:
    return (
        f"System: {SYSTEM_PROMPT}\n\n"
        f"Patient username: {username}\n"
        f"Current mood (1-10): {mood}\n"
        f"Concern: {concern}\n\n"
        f"Give your supportive response."
    )


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_message_counter = 0


class Handler(BaseHTTPRequestHandler):
    # Keep the log short so live traffic is easy to read on the console.
    def log_message(self, *_, **__):
        pass

    def do_POST(self):
        global _message_counter

        if self.path != "/message":
            self._send_error(404, "only POST /message is supported")
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length)
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_error(400, f"malformed JSON request body: {exc}")
            return

        ciphertext = str(payload.get("ciphertext", "")).strip()

        if not ciphertext:
            self._send_error(400, "encrypted 'ciphertext' field is empty")
            return

        _message_counter += 1
        msg_id = f"{_message_counter:03d}"

        # Step 1: decrypt the incoming composite payload (direction CLIENT -> SERVER).
        try:
            composite = affine_decrypt(ciphertext, C2S_A, C2S_B)
        except ValueError as exc:
            self._send_error(400, f"decrypt failed: {exc}")
            return

        # Step 2: parse composite plaintext: username|mood|concern
        try:
            parts = composite.split("|", 2)
            username = parts[0].strip()
            mood = int(parts[1])
            concern = parts[2].strip()
        except (ValueError, IndexError) as exc:
            self._send_error(400, f"malformed composite plaintext: {exc}")
            return

        # Step 3: ask the local LLM for a suggestion.
        try:
            suggestion = ollama_generate(build_prompt(username, mood, concern))
        except _OllamaHTTPError as exc:
            self._send_error(
                503,
                {"error": "LLM_UNAVAILABLE", "detail": str(exc)},
            )
            return

        # Step 3: encrypt the reply (direction SERVER -> CLIENT).
        reply_ciphertext = affine_encrypt(suggestion, S2C_A, S2C_B)

        # Step 4: respond to the client.
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            self.wfile.write(json.dumps({"reply": reply_ciphertext}).encode())
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError) as exc:
            # Client closed the socket (e.g. HTTP timeout) — log and exit cleanly.
            print(
                f"[srv] {msg_id} | client socket closed before reply: {exc}",
                file=sys.stderr,
            )
            return

        # Step 5: log only ciphertexts + metadata (never plaintext).
        print(
            f"[srv] {msg_id} | C2S_ciphertext={ciphertext} | "
            f"S2C_ciphertext={reply_ciphertext} | "
            f"username={username} | mood={mood}"
        )

    def _send_error(
        self,
        status: int,
        detail,
    ) -> None:
        detail_json = detail if isinstance(detail, str) else json.dumps(detail)
        body = json.dumps({"error": detail_json}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = HTTPServer((SERVER_HOST, SERVER_PORT), Handler)
    print(f"[srv] PsycoSupport server listening on {SERVER_HOST}:{SERVER_PORT}")
    print(f"[srv] POST {SERVER_URL}")
    print("[srv] Ollama target:", OLLAMA_URL, "| model:", OLLAMA_MODEL)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[srv] shutting down.")


if __name__ == "__main__":
    main()
