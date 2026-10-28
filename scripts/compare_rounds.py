#!/usr/bin/env python3
"""Compare round counts on identical seeded blocks, keys, and bit flips."""

import argparse
import csv
import hashlib
import json
import random
import statistics
from pathlib import Path

from aes_core import encrypt_block
from security_evaluation import avalanche_ratio, shannon_entropy


def compare(samples=512, seed=42):
    rng = random.Random(seed)
    inputs = [(rng.randbytes(16), rng.randbytes(16), rng.randrange(128), rng.randrange(128))
              for _ in range(samples)]
    rows = []
    for rounds in (4, 6, 8, 10):
        plaintext_scores, key_scores, ciphertexts = [], [], bytearray()
        for block, key, input_bit, key_bit in inputs:
            changed_block, changed_key = bytearray(block), bytearray(key)
            changed_block[input_bit // 8] ^= 1 << (input_bit % 8)
            changed_key[key_bit // 8] ^= 1 << (key_bit % 8)
            ciphertext = encrypt_block(block, key, rounds)
            ciphertexts.extend(ciphertext)
            plaintext_scores.append(100 * avalanche_ratio(ciphertext, encrypt_block(changed_block, key, rounds)))
            key_scores.append(100 * avalanche_ratio(ciphertext, encrypt_block(block, changed_key, rounds)))
        row = {"rounds": rounds, "independent_samples": samples}
        for label, scores in (("plaintext", plaintext_scores), ("key", key_scores)):
            row[f"{label}_avalanche_percent"] = statistics.fmean(scores)
            row[f"{label}_ci95_half_width"] = 1.96 * statistics.stdev(scores) / samples ** 0.5
        row["pooled_entropy_bits_per_byte"] = shannon_entropy(ciphertexts)
        row["ciphertext_sha256"] = hashlib.sha256(ciphertexts).hexdigest()
        rows.append(row)
    return rows


def plot(rows, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
    x = [row["rounds"] for row in rows]
    for ax, label in zip(axes[:2], ("plaintext", "key")):
        ax.errorbar(x, [row[f"{label}_avalanche_percent"] for row in rows],
                    yerr=[row[f"{label}_ci95_half_width"] for row in rows],
                    fmt="o", capsize=5, color="#2667a8")
        ax.axhline(50, color="#777777", linestyle="--", linewidth=1)
        ax.set(title=f"One-bit {label} change", ylabel="Ciphertext bits changed (%)", ylim=(47, 53))
    values = [row["pooled_entropy_bits_per_byte"] for row in rows]
    axes[2].bar(x, values, width=1, color="#39836d")
    axes[2].axhline(8, color="#777777", linestyle="--", linewidth=1)
    axes[2].set(title="Pooled ciphertext byte entropy", ylabel="Empirical entropy (bits/byte)", ylim=(0, 8.5))
    for ax in axes:
        ax.set_xticks(x)
        ax.set_xlabel("AES rounds")
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.2)
    fig.suptitle(f"Same {rows[0]['independent_samples']} random blocks and keys at every round count")
    fig.text(0.5, 0.01, "Error bars: approximate 95% confidence intervals of the mean. Statistical similarity does not establish cryptographic security.",
             ha="center", fontsize=8)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(path, dpi=160)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=512)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-dir", type=Path, default=Path("results/comparison"))
    args = parser.parse_args()
    if args.samples < 2:
        parser.error("--samples must be at least 2")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = compare(args.samples, args.seed)
    with (args.out_dir / "round_comparison.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.out_dir / "methodology.json").write_text(json.dumps({
        "seed": args.seed, "samples": args.samples,
        "design": "Identical independent random blocks, keys, and random single-bit flips at each round count.",
        "confidence_interval": "Mean +/- 1.96 * sample standard deviation / sqrt(samples).",
        "entropy": "Pooled bytes from all ciphertext blocks, not a mean of 16-byte entropies.",
    }, indent=2) + "\n")
    plot(rows, args.out_dir / "round_comparison.png")
    print(f"Saved matched-input comparison to {args.out_dir}")


if __name__ == "__main__":
    main()
