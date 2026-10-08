#!/usr/bin/env python3
"""Generate publication-style graphs from existing AdaptAES result files."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", "/tmp/adaptaes-matplotlib")

import matplotlib.pyplot as plt


BUCKET_ORDER = ["1-128", "129-512", "513-1024", ">1024"]
BUCKET_LABELS = {
    "1-128": "1-128 B",
    "129-512": "129-512 B",
    "513-1024": "513-1024 B",
    ">1024": ">1024 B",
}
MODE_ORDER = ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]
MODE_LABELS = {
    "standard_aes_10": "Standard AES",
    "fixed_reduced_aes_4": "Reduced AES",
    "adaptaes": "AdaptAES",
}
def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def require_columns(rows: list[dict[str, str]], columns: list[str], path: Path) -> None:
    if not rows:
        raise ValueError(f"No rows found in {path}")
    missing = [column for column in columns if column not in rows[0]]
    if missing:
        raise ValueError(f"{path} is missing columns: {', '.join(missing)}")


def validate_performance(rows: list[dict[str, str]]) -> None:
    present = {(row["payload_bucket"], row["mode"]) for row in rows}
    missing = [
        (bucket, mode)
        for bucket in BUCKET_ORDER
        for mode in MODE_ORDER
        if (bucket, mode) not in present
    ]
    if missing:
        formatted = ", ".join(f"{bucket}/{mode}" for bucket, mode in missing)
        raise ValueError(f"Missing payload range/method rows: {formatted}")


def ns_to_ms(value: str) -> float:
    return float(value) / 1_000_000


def style_axes(ax) -> None:
    ax.grid(True, axis="y", linestyle="--", linewidth=0.6, alpha=0.7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def set_zoomed_ylim(ax, values: list[float], reference: float | None = None) -> None:
    all_values = list(values)
    if reference is not None:
        all_values.append(reference)
    minimum = min(all_values)
    maximum = max(all_values)
    span = maximum - minimum
    if span == 0:
        span = abs(maximum) * 0.01 or 0.01
    padding = span * 0.35
    ax.set_ylim(minimum - padding, maximum + padding)


def save(fig, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved {path}")


def graph1_payload_round_selection(rows: list[dict[str, str]], out_dir: Path) -> None:
    standard_rows = {row["payload_bucket"]: row for row in rows if row["mode"] == "standard_aes_10"}
    adaptive_rows = {row["payload_bucket"]: row for row in rows if row["mode"] == "adaptaes"}
    counts = [int(float(standard_rows[bucket]["payload_count"])) for bucket in BUCKET_ORDER]
    total = sum(counts)
    percentages = [count / total * 100 for count in counts]
    rounds = [int(float(adaptive_rows[bucket]["rounds_used"])) for bucket in BUCKET_ORDER]
    x = list(range(len(BUCKET_ORDER)))

    fig, ax_rounds = plt.subplots(figsize=(8.2, 4.8))
    ax_percent = ax_rounds.twinx()

    ax_percent.bar(x, percentages, width=0.45, alpha=0.25, label="Payload share")
    ax_rounds.step(x, rounds, where="mid", linewidth=2.2, marker="o", label="AdaptAES rounds")

    for index, percentage in enumerate(percentages):
        ax_percent.text(index, percentage, f"{percentage:.1f}%", ha="center", va="bottom", fontsize=9)

    ax_rounds.set_xticks(x)
    ax_rounds.set_xticklabels([BUCKET_LABELS[bucket] for bucket in BUCKET_ORDER])
    ax_rounds.set_yticks([4, 6, 8, 10])
    ax_rounds.set_ylabel("AdaptAES Rounds")
    ax_percent.set_ylabel("Payload Share (%)")
    ax_rounds.set_xlabel("Payload Size Range")
    ax_rounds.set_title("Payload Size Distribution and AdaptAES Round Selection")
    style_axes(ax_rounds)
    ax_percent.spines["top"].set_visible(False)

    lines, labels = ax_rounds.get_legend_handles_labels()
    bars, bar_labels = ax_percent.get_legend_handles_labels()
    ax_rounds.legend(lines + bars, labels + bar_labels, loc="upper left")
    save(fig, out_dir / "graph1_payload_round_selection.png")


def grouped_bar(
    rows: list[dict[str, str]],
    out_dir: Path,
    column: str,
    ylabel: str,
    title: str,
    filename: str,
    convert=None,
    modes: list[str] | None = None,
) -> None:
    modes = modes or MODE_ORDER
    by_key = {(row["payload_bucket"], row["mode"]): row for row in rows}
    x = list(range(len(BUCKET_ORDER)))
    width = 0.24 if len(modes) == 3 else 0.34

    fig, ax = plt.subplots(figsize=(8.2, 4.8))
    for mode_index, mode in enumerate(modes):
        offset = (mode_index - (len(modes) - 1) / 2) * width
        values = []
        for bucket in BUCKET_ORDER:
            raw = by_key[(bucket, mode)][column]
            values.append(convert(raw) if convert else float(raw))
        ax.bar([item + offset for item in x], values, width=width, label=MODE_LABELS[mode])

    ax.set_xticks(x)
    ax.set_xticklabels([BUCKET_LABELS[bucket] for bucket in BUCKET_ORDER])
    ax.set_xlabel("Payload Size Range")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend()
    style_axes(ax)
    save(fig, out_dir / filename)


def weighted_method_metrics(rows: list[dict[str, str]]) -> dict[str, dict[str, float]]:
    metrics = [
        "avalanche_percent",
        "key_avalanche_percent",
        "entropy_bits_per_byte",
        "plaintext_ciphertext_correlation",
    ]
    by_mode: dict[str, list[dict[str, str]]] = {mode: [] for mode in MODE_ORDER}
    for row in rows:
        by_mode[row["mode"]].append(row)

    weighted = {}
    for mode, mode_rows in by_mode.items():
        total = sum(int(float(row["payload_count"])) for row in mode_rows)
        weighted[mode] = {
            metric: sum(
                int(float(row["payload_count"])) * float(row[metric])
                for row in mode_rows
            )
            / total
            for metric in metrics
        }
    return weighted


def graph5_security_metrics(rows: list[dict[str, str]], out_dir: Path) -> None:
    by_mode = weighted_method_metrics(rows)
    x = list(range(len(MODE_ORDER)))
    metrics = [
        ("avalanche_percent", "Avalanche Effect (%)", "Avalanche Effect", 50.0),
        ("key_avalanche_percent", "Key Avalanche Effect (%)", "Key Avalanche Effect", 50.0),
        ("entropy_bits_per_byte", "Shannon Entropy", "Shannon Entropy", None),
        ("plaintext_ciphertext_correlation", "Correlation", "Plaintext-Ciphertext Correlation", 0.0),
    ]

    fig, axes = plt.subplots(2, 2, figsize=(9.5, 6.8))
    for ax, (column, ylabel, title, reference) in zip(axes.flat, metrics):
        values = [by_mode[mode][column] for mode in MODE_ORDER]
        for index, (mode, value) in enumerate(zip(MODE_ORDER, values)):
            ax.bar(index, value, width=0.55, label=MODE_LABELS[mode])
            ax.text(index, value, f"{value:.4f}", ha="center", va="bottom", fontsize=8)
        if reference is not None:
            ax.axhline(reference, linestyle="--", linewidth=1)
        set_zoomed_ylim(ax, values, reference)
        ax.set_xticks(x)
        ax.set_xticklabels([MODE_LABELS[mode] for mode in MODE_ORDER], rotation=15, ha="right")
        ax.set_xlabel("Method")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        style_axes(ax)

    fig.suptitle("Security Characteristics Across AES Methods", fontsize=13)
    save(fig, out_dir / "graph5_security_metrics_vs_rounds.png")


def print_validation(performance_path: Path) -> None:
    print("Found performance result:")
    print(f"    {performance_path}")
    print("Using performance columns:")
    print("    payload_bucket, mode, payload_count, rounds_used")
    print("    mean_encryption_time_ns, mean_decryption_time_ns")
    print("    time_reduction_percent_vs_aes10")
    print("Using security/statistical columns from the same file:")
    print("    avalanche_percent, key_avalanche_percent")
    print("    entropy_bits_per_byte, plaintext_ciphertext_correlation")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-dir", type=Path, default=Path("results/analysis"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/plots"))
    args = parser.parse_args()

    performance_path = args.analysis_dir / "bucket_security_performance_summary.csv"
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    performance_rows = read_csv(performance_path)
    performance_columns = [
        "payload_bucket",
        "mode",
        "payload_count",
        "rounds_used",
        "mean_encryption_time_ns",
        "mean_decryption_time_ns",
        "time_reduction_percent_vs_aes10",
        "avalanche_percent",
        "key_avalanche_percent",
        "entropy_bits_per_byte",
        "plaintext_ciphertext_correlation",
    ]
    require_columns(performance_rows, performance_columns, performance_path)
    validate_performance(performance_rows)
    print_validation(performance_path)

    graph1_payload_round_selection(performance_rows, out_dir)
    grouped_bar(
        performance_rows,
        out_dir,
        column="mean_encryption_time_ns",
        ylabel="Mean Encryption Time (ms)",
        title="Encryption Time Comparison by Payload Size",
        filename="graph2_encryption_time.png",
        convert=ns_to_ms,
    )
    grouped_bar(
        performance_rows,
        out_dir,
        column="mean_decryption_time_ns",
        ylabel="Mean Decryption Time (ms)",
        title="Decryption Time Comparison by Payload Size",
        filename="graph3_decryption_time.png",
        convert=ns_to_ms,
    )
    grouped_bar(
        performance_rows,
        out_dir,
        column="time_reduction_percent_vs_aes10",
        ylabel="Encryption Time Reduction vs AES-10 (%)",
        title="AdaptAES Encryption Time Reduction Relative to Standard AES-10",
        filename="graph4_encryption_reduction.png",
        modes=["adaptaes"],
    )
    graph5_security_metrics(performance_rows, out_dir)


if __name__ == "__main__":
    main()
