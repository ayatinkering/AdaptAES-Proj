#!/usr/bin/env python3
"""Print report-ready AdaptAES security metric tables."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


MODE_LABELS = {
    "standard_aes_10": "Standard AES",
    "fixed_reduced_aes_4": "Reduced AES",
    "adaptaes": "AdaptAES",
}

ROUND_LABELS = {
    "standard_aes_10": "10",
    "fixed_reduced_aes_4": "4",
    "adaptaes": "4/6/8/10",
}

BUCKET_LABELS = {
    "1-128": "Small (1-128 B)",
    "129-512": "Medium (129-512 B)",
    "513-1024": "Large (513-1024 B)",
    ">1024": "Very Large (>1024 B)",
}


def fmt(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def print_title(title: str) -> None:
    print("\n" + "=" * 130)
    print(title)
    print("=" * 130)


def print_table(headers: list[str], rows: list[list[object]]) -> None:
    string_rows = [[fmt(cell) for cell in row] for row in rows]
    widths = [
        max(len(str(header)), *(len(row[index]) for row in string_rows))
        for index, header in enumerate(headers)
    ]
    print(" | ".join(str(header).ljust(widths[index]) for index, header in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in string_rows:
        print(" | ".join(row[index].ljust(widths[index]) for index in range(len(headers))))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def observation(row: dict[str, str]) -> str:
    avalanche = float(row["mean_plaintext_avalanche_percent"])
    entropy = float(row["mean_ciphertext_entropy"])
    correlation = abs(float(row["mean_correlation_coefficient"]))

    if 45 <= avalanche <= 55 and entropy >= 7.5 and correlation <= 0.10:
        return "Strong diffusion/randomness"
    if 35 <= avalanche <= 65 and entropy >= 7.0 and correlation <= 0.20:
        return "Moderate diffusion/randomness"
    return "Weaker statistical behavior"


def print_overall_security(security_dir: Path) -> None:
    rows = load_csv(security_dir / "security_mode_summary.csv")
    ordered = sorted(rows, key=lambda row: ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"].index(row["mode"]))
    table_rows = []
    for row in ordered:
        table_rows.append(
            [
                MODE_LABELS[row["mode"]],
                ROUND_LABELS[row["mode"]],
                int(float(row["sample_count"])),
                float(row["mean_ciphertext_entropy"]),
                float(row["mean_plaintext_avalanche_percent"]),
                float(row["mean_key_avalanche_percent"]),
                float(row["mean_byte_frequency_stddev"]),
                float(row["mean_chi_square"]),
                float(row["mean_correlation_coefficient"]),
                observation(row),
            ]
        )

    print_title("TABLE 1: OVERALL SECURITY METRIC COMPARISON")
    print_table(
        [
            "Method",
            "Rounds",
            "Samples",
            "Entropy",
            "Plaintext Avalanche %",
            "Key Avalanche %",
            "Byte Freq StdDev",
            "Chi-Square",
            "Correlation",
            "Observation",
        ],
        table_rows,
    )


def print_bucket_security(security_dir: Path) -> None:
    rows = load_csv(security_dir / "security_bucket_summary.csv")
    bucket_order = ["1-128", "129-512", "513-1024", ">1024"]
    mode_order = ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]
    ordered = sorted(
        rows,
        key=lambda row: (bucket_order.index(row["payload_bucket"]), mode_order.index(row["mode"])),
    )

    table_rows = []
    for row in ordered:
        table_rows.append(
            [
                BUCKET_LABELS[row["payload_bucket"]],
                MODE_LABELS[row["mode"]],
                int(float(row["sample_count"])),
                float(row["mean_payload_length"]),
                float(row["mean_rounds_used"]),
                float(row["mean_ciphertext_entropy"]),
                float(row["mean_plaintext_avalanche_percent"]),
                float(row["mean_key_avalanche_percent"]),
                float(row["mean_chi_square"]),
                float(row["mean_correlation_coefficient"]),
            ]
        )

    print_title("TABLE 2: SECURITY METRICS BY PAYLOAD SIZE RANGE")
    print_table(
        [
            "Payload Range",
            "Method",
            "Samples",
            "Avg Size (B)",
            "Avg Rounds",
            "Entropy",
            "Plaintext Avalanche %",
            "Key Avalanche %",
            "Chi-Square",
            "Correlation",
        ],
        table_rows,
    )


def print_interpretation_guide() -> None:
    print_title("TABLE 3: SECURITY METRIC INTERPRETATION GUIDE")
    print_table(
        ["Metric", "What It Shows", "Better Direction"],
        [
            ["Avalanche Effect", "Ciphertext change after 1 plaintext bit flip", "Closer to 50%"],
            ["Key Avalanche Effect", "Ciphertext change after 1 key bit flip", "Closer to 50%"],
            ["Shannon Entropy", "Ciphertext byte randomness", "Closer to 8"],
            ["Byte Frequency StdDev", "Spread of byte frequencies", "Lower"],
            ["Chi-Square", "Uniformity of byte distribution", "Lower"],
            ["Correlation Coefficient", "Plaintext-ciphertext relationship", "Closer to 0"],
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--security-dir", type=Path, default=Path("results/security"))
    args = parser.parse_args()

    print_overall_security(args.security_dir)
    print_bucket_security(args.security_dir)
    print_interpretation_guide()


if __name__ == "__main__":
    main()
