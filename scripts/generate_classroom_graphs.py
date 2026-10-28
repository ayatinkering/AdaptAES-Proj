#!/usr/bin/env python3
"""Build teaching figures from recorded data, without rerunning encryption."""

import csv
import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from generate_graphs import grouped_bar, ns_to_ms

OUT = Path("results/classroom/plots")
BUCKETS = ["1-128", "129-512", "513-1024", ">1024"]
COLORS = ["#2667a8", "#ca7745", "#39836d"]


def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=160, bbox_inches="tight")
    plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    for path in Path("results/extracted").glob("*_summary.json"):
        counts.update(json.loads(path.read_text())["payload_bins"])
    fig, ax = plt.subplots(figsize=(8, 3.8))
    values = [100 * counts[b] / sum(counts.values()) for b in BUCKETS]
    bars = ax.bar(BUCKETS, values, color=COLORS[0])
    ax.bar_label(bars, labels=[f"{v:.1f}%\n{r} rounds" for v, r in zip(values, (4, 6, 8, 10))], padding=4)
    ax.set(title="Most captured payloads select full 10-round AES", xlabel="Payload bytes", ylabel="Share of payload packets (%)", ylim=(0, 80))
    fig.text(0.5, 0.01, f"All {sum(counts.values()):,} payload packets across six captures", ha="center", fontsize=9)
    save(fig, "traffic_distribution.png")

    timing_dir = Path("results/classroom/timings")
    with (timing_dir / "bucket_timing_summary.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    grouped_bar(rows, OUT, "mean_encryption_time_ns", "Mean encryption time (ms)",
                "Encryption by payload size: warm-up + median of 5 repeats", "encryption_by_size.png", ns_to_ms)
    grouped_bar(rows, OUT, "mean_decryption_time_ns", "Mean decryption time (ms)",
                "Decryption by payload size: warm-up + median of 5 repeats", "decryption_by_size.png", ns_to_ms)
    summary = json.loads((timing_dir / "combined_timing_summary.json").read_text())
    baseline = summary["aggregate_modes"]["standard_aes_10"]["mean_encryption_time_ns"]
    reductions = []
    for bucket in BUCKETS:
        ref = next(float(r["mean_encryption_time_ns"]) for r in rows if r["payload_bucket"] == bucket and r["mode"] == "standard_aes_10")
        adaptive = next(float(r["mean_encryption_time_ns"]) for r in rows if r["payload_bucket"] == bucket and r["mode"] == "adaptaes")
        reductions.append(100 * (1 - adaptive / ref))
    reductions.append(100 * (1 - summary["aggregate_modes"]["adaptaes"]["mean_encryption_time_ns"] / baseline))
    fig, ax = plt.subplots(figsize=(8, 3.8))
    bars = ax.bar(BUCKETS + ["Overall"], reductions, color=[COLORS[2] if n >= 0 else COLORS[1] for n in reductions])
    ax.bar_label(bars, labels=[f"{n:+.1f}%" for n in reductions], padding=4)
    ax.axhline(0, color="#555555", linewidth=1)
    ax.set(title="Round reduction helps smaller payloads; overall benefit is limited", xlabel="Payload bytes", ylabel="Encryption time saved vs AES-10 (%)", ylim=(min(-12, min(reductions)-6), 75))
    fig.text(0.5, 0.01, "300 payloads, 5 timed repeats each. Small overall differences can reflect machine noise.", ha="center", fontsize=9)
    save(fig, "adaptive_savings.png")

    runtime = json.loads(Path("results/runtime/comparison.json").read_text())
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, operation in zip(axes, ("encryption", "decryption")):
        for i, label in enumerate(("before", "after")):
            values = [row[f"{label}_{operation}"]["wall_ms"] for row in runtime["workloads"]]
            ax.bar([x + (i - 0.5) * 0.35 for x in range(3)], values, width=0.35, label=label.title(), color=COLORS[i * 2])
        ax.set_xticks(range(3), [str(row["payload_bytes"]) for row in runtime["workloads"]])
        ax.set(title=operation.title(), xlabel="Payload bytes", ylabel="Median time (ms)")
        ax.legend()
    fig.suptitle("Same AES-10 workload before and after implementation optimizations")
    fig.text(0.5, 0.01, f"Same interpreter and host, interleaved {runtime['repeats']} repeats; wall time, not a new cipher comparison.", ha="center", fontsize=8)
    save(fig, "implementation_speed.png")
    print(f"Saved classroom figures to {OUT}")


if __name__ == "__main__":
    main()
