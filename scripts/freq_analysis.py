#!/usr/bin/env python3
"""
PsycoSupport affine-cipher frequency analysis (Task 3).

Prints ONLY:
  1. C2S (client -> server) letter-frequency table.
  2. S2C (server -> client) letter-frequency table.
  3. Standard English letter-frequency reference table.

Also EXPORTS two matplotlib figures:
  - scripts/charts/counts.png        : C2S + S2C letter counts (descending).
  - scripts/charts/relative_freq.png : all 3 streams, relative frequency % (descending).

No decryption, no key solving. Read-only on ciphers.csv.
"""

import csv
import os
from collections import Counter
from matplotlib import pyplot as plt

ENGLISH_RANK = "etaoinshrdlcumwfgypbvkjxqz"

# Approximate English letter frequencies (%) — descending order.
ENGLISH = [
    ("e", 12.70), ("t", 9.10),  ("a", 8.20),  ("o", 7.50),  ("i", 7.00),
    ("n", 6.80),  ("s", 6.30),  ("h", 6.10),  ("r", 6.00),  ("d", 4.30),
    ("l", 4.30),  ("c", 2.80),  ("u", 2.80),  ("m", 2.80),  ("w", 2.80),
    ("f", 2.30),  ("g", 2.00),  ("y", 2.00),  ("p", 2.20),  ("b", 1.50),
    ("v", 1.00),  ("k", 0.80),  ("j", 0.15),  ("x", 0.15),  ("q", 0.10),
    ("z", 0.08),
]


def frequency_table(text):
    """Lowercase counts over alphabetic chars only; returns sorted (letter, count)."""
    counts = Counter(ch.lower() for ch in text if ch.isalpha())
    total = sum(counts.values())
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return counts, total, ranked


def print_freq_table(title, ranked, total):
    print(f"\n=== {title} ===")
    print(f"alphabetic chars = {total}")
    print(f"{'letter':>6} | {'count':>5} | {'pct':>6} | bar")
    print("-" * 36)
    for letter, count in ranked:
        pct = 100.0 * count / total
        bar = "#" * max(1, round(pct / 2.5))
        print(f"{letter:>6} | {count:>5} | {pct:>6.2f}% | {bar}")


def print_english_table():
    print("\n=== Standard English letter-frequency table ===")
    print(f"{'letter':>6} | {'pct':>6} | rank | bar")
    print("-" * 36)
    for i, (letter, pct) in enumerate(ENGLISH, 1):
        bar = "#" * max(1, round(pct / 2.5))
        print(f"{letter:>6} | {pct:>6.2f}% | {i:>4} | {bar}")


def print_rank_alignment(c2s_ranked, s2c_ranked):
    n = max(len(c2s_ranked), len(s2c_ranked), 26)
    c2s_letters = [c for c, _ in c2s_ranked] + ["."] * max(0, n - len(c2s_ranked))
    s2c_letters = [c for c, _ in s2c_ranked] + ["."] * max(0, n - len(s2c_ranked))
    print("\n=== Side-by-side: cipher rank vs. English rank ===")
    print(f"{'rank':>5} | {'C2S cipher':>10} | {'English':>8} | {'S2C cipher':>10}")
    print("-" * 46)
    for i in range(n):
        eng = ENGLISH_RANK[i] if i < len(ENGLISH_RANK) else "·"
        print(f"{i+1:>5} | {c2s_letters[i]:>10} | {eng:>8} | {s2c_letters[i]:>10}")


def export_counts_chart(c2s_ranked, s2c_ranked, outdir):
    """One figure, two side-by-side bar charts of C2S and S2C letter counts (descending)."""
    fig, axes = plt.subplots(1, 2, figsize=(16, 6), sharey=False)
    fig.suptitle("Letter counts in ciphertexts (descending)", fontsize=14)

    for ax, ranked, label in (
        (axes[0], c2s_ranked, "C2S (client -> server)"),
        (axes[1], s2c_ranked, "S2C (server -> client)"),
    ):
        letters = [c for c, _ in ranked]
        counts = [cnt for _, cnt in ranked]
        ax.bar(letters, counts, color="steelblue")
        ax.set_title(label)
        ax.set_xlabel("cipher letter")
        ax.set_ylabel("count")
        ax.grid(axis="y", linestyle=":", alpha=0.4)
        for l, c in zip(letters, counts):
            ax.text(l, c, str(c), ha="center", va="bottom", fontsize=8)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    path = os.path.join(outdir, "counts.png")
    fig.savefig(path, dpi=120)
    plt.close(fig)
    print(f"\nsaved: {path}")


def export_relative_freq_chart(c2s_ranked, s2c_ranked, outdir):
    """One figure, three bar charts of relative frequency % (descending)."""
    fig, axes = plt.subplots(1, 3, figsize=(20, 6), sharey=True)
    fig.suptitle("Relative letter frequency (%) (descending)", fontsize=14)

    c2s_pct = [(c, 100.0 * cnt / sum(n for _, n in c2s_ranked)) for c, cnt in c2s_ranked]
    s2c_pct = [(c, 100.0 * cnt / sum(n for _, n in s2c_ranked)) for c, cnt in s2c_ranked]
    eng_pct = list(ENGLISH)

    for ax, data, label in (
        (axes[0], c2s_pct, "C2S (client -> server)"),
        (axes[1], s2c_pct, "S2C (server -> client)"),
        (axes[2], eng_pct, "Standard English"),
    ):
        letters = [c for c, _ in data]
        pcts = [round(p, 2) for _, p in data]
        ax.bar(letters, pcts, color="steelblue")
        ax.set_title(label)
        ax.set_xlabel("letter")
        ax.grid(axis="y", linestyle=":", alpha=0.4)
        for l, p in zip(letters, pcts):
            ax.text(l, p, f"{p:.1f}", ha="center", va="bottom", fontsize=7)

    axes[0].set_ylabel("relative frequency (%)")
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    path = os.path.join(outdir, "relative_freq.png")
    fig.savefig(path, dpi=120)
    plt.close(fig)
    print(f"saved: {path}")


def main():
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ciphers.csv")
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "charts")

    with open(csv_path, newline="") as f:
        rows = list(csv.DictReader(f))

    c2s_text = "".join(r["ciphertext"] for r in rows if r["direction"] == "C2S")
    s2c_text = "".join(r["ciphertext"] for r in rows if r["direction"] == "S2C")

    c2s_counts, c2s_total, c2s_ranked = frequency_table(c2s_text)
    s2c_counts, s2c_total, s2c_ranked = frequency_table(s2c_text)

    print_freq_table("C2S (client -> server) frequencies", c2s_ranked, c2s_total)
    print_freq_table("S2C (server -> client) frequencies", s2c_ranked, s2c_total)
    print_english_table()
    print_rank_alignment(c2s_ranked, s2c_ranked)

    os.makedirs(outdir, exist_ok=True)
    export_counts_chart(c2s_ranked, s2c_ranked, outdir)
    export_relative_freq_chart(c2s_ranked, s2c_ranked, outdir)

    print("\nDone. Tables printed above; charts written to:")
    print(f"  {outdir}/counts.png")
    print(f"  {outdir}/relative_freq.png")


if __name__ == "__main__":
    main()
