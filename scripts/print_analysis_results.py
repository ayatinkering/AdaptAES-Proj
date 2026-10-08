#!/usr/bin/env python3
"""Print detailed tables from security_performance_analysis.py outputs."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


MODE_LABELS = {
    "standard_aes_10": "Standard AES",
    "fixed_reduced_aes_4": "Reduced AES",
    "adaptaes": "AdaptAES",
}

BUCKET_LABELS = {
    "1-128": "Small (1-128 B)",
    "129-512": "Medium (129-512 B)",
    "513-1024": "Large (513-1024 B)",
    ">1024": "Very Large (>1024 B)",
}

BUCKET_ORDER = ["1-128", "129-512", "513-1024", ">1024"]
MODE_ORDER = ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]


def security_margin_score(rounds: float) -> float:
    return rounds / 10.0 * 100.0


def security_margin_label(rounds: float) -> str:
    if rounds >= 10:
        return "Full"
    if rounds >= 8:
        return "High"
    if rounds >= 6:
        return "Medium"
    return "Low"


def statistical_result(row: dict[str, str]) -> str:
    avalanche = abs(float(row["avalanche_percent"]) - 50.0)
    key_avalanche = abs(float(row["key_avalanche_percent"]) - 50.0)
    correlation = abs(float(row["plaintext_ciphertext_correlation"]))
    if avalanche <= 1.0 and key_avalanche <= 1.0 and correlation <= 0.05:
        return "Comparable"
    return "Weaker"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def number(value: str | None) -> float | None:
    if value in (None, "", "None"):
        return None
    return float(value)


def fmt(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def ms(ns: str | None) -> float | None:
    val = number(ns)
    return None if val is None else val / 1_000_000


def print_title(title: str) -> None:
    print("\n" + "=" * 150)
    print(title)
    print("=" * 150)


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


def print_coverage(analysis_dir: Path) -> None:
    data = read_json(analysis_dir / "security_performance_summary.json")
    print_title("TABLE 1: ANALYSIS COVERAGE")
    print_table(
        ["Parameter", "Value"],
        [
            ["Payload records analyzed", f"{data['payload_records_available']:,}"],
            ["Timing rows available", f"{data['timing_rows_available']:,}"],
            ["Analysis limit per dataset", data["analysis_limit_per_dataset"] or "None, all payloads"],
            ["Security measurement", data["security_measurement"]],
            ["Payload source", data["payload_note"]],
        ],
    )


def print_roundwise_security(analysis_dir: Path) -> None:
    rows = read_csv(analysis_dir / "roundwise_security_summary.csv")
    table_rows = []
    for row in rows:
        table_rows.append(
            [
                int(float(row["rounds"])),
                f"{int(float(row['sample_count'])):,}",
                float(row["avalanche_percent"]),
                float(row["key_avalanche_percent"]),
                float(row["entropy_bits_per_byte"]),
                float(row["chi_square"]),
                float(row["plaintext_ciphertext_correlation"]),
                float(row["npcr_byte_percent"]),
                float(row["uaci_byte_percent"]),
            ]
        )
    print_title("TABLE 2: ROUND-WISE SECURITY SUMMARY")
    print_table(
        [
            "Rounds",
            "Samples",
            "Avalanche %",
            "Key Avalanche %",
            "Entropy",
            "Chi-Square",
            "Correlation",
            "NPCR %",
            "UACI %",
        ],
        table_rows,
    )


def print_bucket_side_by_side(analysis_dir: Path) -> None:
    rows = read_csv(analysis_dir / "bucket_security_performance_summary.csv")
    by_key = {(row["payload_bucket"], row["mode"]): row for row in rows}
    table_rows = []
    for bucket in BUCKET_ORDER:
        standard = by_key[(bucket, "standard_aes_10")]
        reduced = by_key[(bucket, "fixed_reduced_aes_4")]
        adaptive = by_key[(bucket, "adaptaes")]
        table_rows.append(
            [
                BUCKET_LABELS[bucket],
                f"{int(float(standard['payload_count'])):,}",
                float(standard["average_payload_bytes"]),
                f"{ms(standard['mean_encryption_time_ns']):.2f} / {ms(standard['mean_decryption_time_ns']):.2f}",
                f"{ms(reduced['mean_encryption_time_ns']):.2f} / {ms(reduced['mean_decryption_time_ns']):.2f}",
                f"{ms(adaptive['mean_encryption_time_ns']):.2f} / {ms(adaptive['mean_decryption_time_ns']):.2f}",
                int(float(adaptive["rounds_used"])),
                security_margin_label(float(adaptive["rounds_used"])),
                security_margin_score(float(adaptive["rounds_used"])),
                float(adaptive["time_reduction_percent_vs_aes10"]),
                float(adaptive["avalanche_percent"]),
                float(adaptive["entropy_bits_per_byte"]),
                float(adaptive["plaintext_ciphertext_correlation"]),
            ]
        )
    print_title("TABLE 3: PAYLOAD-RANGE RESULT SUMMARY")
    print_table(
        [
            "Payload Range",
            "Payloads",
            "Avg Size (B)",
            "Standard Enc/Dec (ms)",
            "Reduced Enc/Dec (ms)",
            "AdaptAES Enc/Dec (ms)",
            "AdaptAES Rounds",
            "Margin",
            "Margin Score",
            "AdaptAES Enc Reduction %",
            "AdaptAES Avalanche %",
            "AdaptAES Entropy",
            "AdaptAES Correlation",
        ],
        table_rows,
    )


def print_full_bucket_comparison(analysis_dir: Path) -> None:
    rows = read_csv(analysis_dir / "bucket_security_performance_summary.csv")
    ordered = sorted(
        rows,
        key=lambda row: (BUCKET_ORDER.index(row["payload_bucket"]), MODE_ORDER.index(row["mode"])),
    )
    table_rows = []
    for row in ordered:
        table_rows.append(
            [
                BUCKET_LABELS[row["payload_bucket"]],
                MODE_LABELS[row["mode"]],
                int(float(row["rounds_used"])),
                security_margin_label(float(row["rounds_used"])),
                security_margin_score(float(row["rounds_used"])),
                int(float(row["timing_sample_count"])),
                ms(row["mean_encryption_time_ns"]),
                ms(row["mean_decryption_time_ns"]),
                number(row.get("speedup_vs_aes10")),
                number(row.get("time_reduction_percent_vs_aes10")),
                float(row["avalanche_percent"]),
                float(row["key_avalanche_percent"]) if "key_avalanche_percent" in row else None,
                float(row["entropy_bits_per_byte"]),
                float(row["chi_square"]),
                float(row["plaintext_ciphertext_correlation"]),
            ]
        )
    print_title("TABLE 4: FULL PERFORMANCE + SECURITY COMPARISON BY RANGE")
    print_table(
        [
            "Payload Range",
            "Method",
            "Rounds",
            "Margin",
            "Margin Score",
            "Timing n",
            "Enc ms",
            "Dec ms",
            "Speedup",
            "Enc Reduction %",
            "Avalanche %",
            "Key Avalanche %",
            "Entropy",
            "Chi-Square",
            "Correlation",
        ],
        table_rows,
    )


def print_security_margin_comparison(analysis_dir: Path) -> None:
    rows = read_csv(analysis_dir / "bucket_security_performance_summary.csv")
    by_mode: dict[str, list[dict[str, str]]] = {mode: [] for mode in MODE_ORDER}
    for row in rows:
        by_mode[row["mode"]].append(row)

    table_rows = []
    for mode in MODE_ORDER:
        mode_rows = by_mode[mode]
        total_payloads = sum(int(float(row["payload_count"])) for row in mode_rows)
        weighted_rounds = sum(
            int(float(row["payload_count"])) * float(row["rounds_used"])
            for row in mode_rows
        ) / total_payloads
        weighted_reduction = sum(
            int(float(row["payload_count"])) * number(row["time_reduction_percent_vs_aes10"])
            for row in mode_rows
        ) / total_payloads
        comparable_rows = sum(1 for row in mode_rows if statistical_result(row) == "Comparable")
        table_rows.append(
            [
                MODE_LABELS[mode],
                f"{total_payloads:,}",
                weighted_rounds,
                security_margin_score(weighted_rounds),
                security_margin_label(weighted_rounds),
                f"{comparable_rows}/{len(mode_rows)} ranges comparable",
                weighted_reduction,
            ]
        )

    print_title("TABLE 5: SECURITY MARGIN COMPARISON")
    print_table(
        [
            "Method",
            "Payloads",
            "Weighted Avg Rounds",
            "Margin Score",
            "Margin Level",
            "Statistical Tests",
            "Weighted Enc Reduction %",
        ],
        table_rows,
    )


def print_security_claim_table(analysis_dir: Path) -> None:
    rows = read_csv(analysis_dir / "bucket_security_performance_summary.csv")
    ordered = sorted(
        rows,
        key=lambda row: (BUCKET_ORDER.index(row["payload_bucket"]), MODE_ORDER.index(row["mode"])),
    )
    table_rows = []
    for row in ordered:
        rounds = float(row["rounds_used"])
        table_rows.append(
            [
                BUCKET_LABELS[row["payload_bucket"]],
                MODE_LABELS[row["mode"]],
                int(rounds),
                statistical_result(row),
                security_margin_label(rounds),
                "Fastest but lowest margin"
                if row["mode"] == "fixed_reduced_aes_4"
                else "Full AES baseline"
                if row["mode"] == "standard_aes_10"
                else "Adaptive trade-off",
            ]
        )

    print_title("TABLE 6: STATISTICAL SECURITY VS SECURITY MARGIN")
    print_table(
        ["Payload Range", "Method", "Rounds", "Statistical Result", "Security Margin", "Project Interpretation"],
        table_rows,
    )


def print_byte_frequency_summary(analysis_dir: Path) -> None:
    rows = read_csv(analysis_dir / "byte_frequency_by_round.csv")
    by_round: dict[int, list[int]] = {}
    sample_count: dict[int, int] = {}
    for row in rows:
        rounds = int(float(row["rounds"]))
        by_round.setdefault(rounds, []).append(int(float(row["count"])))
        sample_count[rounds] = int(float(row["sample_count"]))
    table_rows = []
    for rounds in sorted(by_round):
        counts = by_round[rounds]
        mean_count = sum(counts) / len(counts)
        variance = sum((count - mean_count) ** 2 for count in counts) / len(counts)
        table_rows.append(
            [
                rounds,
                f"{sample_count[rounds]:,}",
                min(counts),
                max(counts),
                mean_count,
                variance ** 0.5,
            ]
        )
    print_title("TABLE 7: BYTE FREQUENCY DISTRIBUTION BY ROUND COUNT")
    print_table(
        ["Rounds", "Blocks", "Min Byte Count", "Max Byte Count", "Mean Count", "StdDev"],
        table_rows,
    )


def print_interpretation() -> None:
    print_title("TABLE 8: HOW TO READ THESE RESULTS")
    print_table(
        ["Result", "Meaning for project"],
        [
            ["Reduced AES timing", "Fastest because every payload uses only 4 rounds."],
            ["AdaptAES timing", "Varies by packet size: 4 rounds for small, 6/8 for middle ranges, 10 for very large."],
            ["Standard AES timing", "Slowest baseline because every payload uses 10 rounds."],
            ["Margin score", "Rounds expressed as a percentage of full AES-10. 4 rounds = 40, 10 rounds = 100."],
            ["Comparable statistics", "Means the tested diffusion/randomness metrics are close, not that reduced AES is cryptographically equal."],
            ["Avalanche near 50%", "Shows strong block-level diffusion in this statistical test."],
            ["Entropy around 3.94 here", "Measured on one 16-byte block, so empirical entropy is capped at log2(16)=4."],
            ["Correlation near 0", "Shows low direct plaintext-ciphertext byte relationship."],
            ["Security margin result", "Standard AES has full margin, Reduced AES has low margin, and AdaptAES sits between them."],
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analysis-dir", type=Path, default=Path("results/analysis"))
    args = parser.parse_args()

    print_coverage(args.analysis_dir)
    print_roundwise_security(args.analysis_dir)
    print_bucket_side_by_side(args.analysis_dir)
    print_full_bucket_comparison(args.analysis_dir)
    print_security_margin_comparison(args.analysis_dir)
    print_security_claim_table(args.analysis_dir)
    print_byte_frequency_summary(args.analysis_dir)
    print_interpretation()


if __name__ == "__main__":
    main()
