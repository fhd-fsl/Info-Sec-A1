#!/usr/bin/env python3
"""
PsycoSupport -- shared configuration.

All constants shared between server and client live here so they can be
changed in one place:

  * affine cipher keys (C2S = client->server, S2C = server->client)
  * network endpoints (server address/port)
  * the local Ollama model to call for suggestions

IMPORTANT: for this lab the keys are hard-coded here. To switch the running
key pair for a fresh set of ciphertexts, edit ONLY this file and restart
both processes. Never commit the real keys to version control.
"""

# ---------------------------------------------------------------------------
# AFFINE CIPHER KEYS (must be identical in every process that uses them)
# ---------------------------------------------------------------------------

# Client->Server: the client encrypts with this, the server decrypts with it.
C2S_A = 5
C2S_B = 8

# Server->Client: the server encrypts with this, the client decrypts with it.
S2C_A = 7
S2C_B = 3


# ---------------------------------------------------------------------------
# NETWORK CONFIG
# ---------------------------------------------------------------------------

# Server binds to this address:port. Clients connect here.
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

# Client connects to this URL.
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}/message"

# ---------------------------------------------------------------------------
# LOCAL LLM CONFIG
# ---------------------------------------------------------------------------

# Ollama host + model. gemma4:e4b is the model you want to use on this machine.
OLLAMA_URL = "http://127.0.0.1:11434"
OLLAMA_MODEL = "gemma4:e4b"

# Number of attempts + socket timeout (seconds) when calling the Ollama API.
OLLAMA_RETRIES = 3
OLLAMA_TIMEOUT = 180


# ---------------------------------------------------------------------------
# SELF-CHECKS (fail loud at import time if config is inconsistent)
# ---------------------------------------------------------------------------

import math


def _check_key(a, b, name):
    if not isinstance(a, int) or not isinstance(b, int):
        raise SystemExit(f"{name}: keys must be integers, got {a!r} / {b!r}")
    if math.gcd(a, 26) != 1:
        raise SystemExit(
            f"invalid affine key {name}=(a={a}, b={b}): gcd({a}, 26) != 1, "
            f"cannot decrypt; choose a in {{1,3,5,7,9,11,15,17,19,21,23,25}}"
        )


_check_key(C2S_A, C2S_B, "C2S")
_check_key(S2C_A, S2C_B, "S2C")

print("[config] loaded keys: C2S=(%d, %d) | S2C=(%d, %d)"
      % (C2S_A, C2S_B, S2C_A, S2C_B))
print("[config] Ollama: %s | model: %s" % (OLLAMA_URL, OLLAMA_MODEL))
