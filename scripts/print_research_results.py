#!/usr/bin/env python3
"""Print report-ready AdaptAES result tables in the terminal."""

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


def ns_to_ms(value: float) -> float:
    return value / 1_000_000


def fmt(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def print_title(title: str) -> None:
    print("\n" + "=" * 110)
    print(title)
    print("=" * 110)


def print_table(headers: list[str], rows: list[list[object]]) -> None:
    string_rows = [[fmt(cell) for cell in row] for row in rows]
    widths = [
        max(len(str(header)), *(len(row[index]) for row in string_rows))
        for index, header in enumerate(headers)
    ]

    header_line = " | ".join(str(header).ljust(widths[index]) for index, header in enumerate(headers))
    separator = "-+-".join("-" * width for width in widths)
    print(header_line)
    print(separator)
    for row in string_rows:
        print(" | ".join(row[index].ljust(widths[index]) for index in range(len(headers))))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def print_dataset_overview(extracted_dir: Path) -> None:
    rows = []
    total_packets = 0
    total_payload_packets = 0
    total_tcp = 0
    total_udp = 0

    for summary_path in sorted(extracted_dir.glob("*_summary.json")):
        data = load_json(summary_path)
        dataset = Path(data["pcap"]).stem
        packets = int(data["total_packets"])
        payload_packets = int(data["packets_with_payload"])
        tcp = int(data["protocol_counts"].get("TCP", 0))
        udp = int(data["protocol_counts"].get("UDP", 0))
        total_packets += packets
        total_payload_packets += payload_packets
        total_tcp += tcp
        total_udp += udp
        rows.append(
            [
                dataset,
                f"{packets:,}",
                f"{payload_packets:,}",
                f"{payload_packets / packets * 100:.2f}%",
                f"{tcp:,}",
                f"{udp:,}",
            ]
        )

    rows.append(
        [
            "TOTAL",
            f"{total_packets:,}",
            f"{total_payload_packets:,}",
            f"{total_payload_packets / total_packets * 100:.2f}%",
            f"{total_tcp:,}",
            f"{total_udp:,}",
        ]
    )

    print_title("TABLE 1: PCAP DATASET OVERVIEW")
    print_table(
        [
            "Dataset",
            "Total Packets",
            "Payload Packets",
            "Payload %",
            "TCP",
            "UDP",
        ],
        rows,
    )


def print_payload_distribution(extracted_dir: Path) -> None:
    bucket_order = ["1-128", "129-512", "513-1024", ">1024"]
    totals = {bucket: 0 for bucket in bucket_order}
    total_payload_packets = 0

    for summary_path in sorted(extracted_dir.glob("*_summary.json")):
        data = load_json(summary_path)
        total_payload_packets += int(data["packets_with_payload"])
        for bucket in bucket_order:
            totals[bucket] += int(data["payload_bins"].get(bucket, 0))

    rows = []
    for bucket in bucket_order:
        count = totals[bucket]
        rows.append(
            [
                BUCKET_LABELS[bucket],
                f"{count:,}",
                f"{count / total_payload_packets * 100:.2f}%",
                "Adaptive round selection",
                {"1-128": "4", "129-512": "6", "513-1024": "8", ">1024": "10"}[bucket],
            ]
        )

    print_title("TABLE 2: PAYLOAD SIZE DISTRIBUTION AND ADAPTAES ROUND POLICY")
    print_table(
        [
            "Payload Range",
            "Packet Count",
            "Dataset Share",
            "Policy Type",
            "AdaptAES Rounds",
        ],
        rows,
    )


def speedup_rows(aggregate_modes: dict) -> list[list[object]]:
    standard = aggregate_modes["standard_aes_10"]
    rows = []
    for mode in ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]:
        stats = aggregate_modes[mode]
        enc_ms = ns_to_ms(float(stats["mean_encryption_time_ns"]))
        dec_ms = ns_to_ms(float(stats["mean_decryption_time_ns"]))
        standard_enc = float(standard["mean_encryption_time_ns"])
        standard_dec = float(standard["mean_decryption_time_ns"])
        enc_speedup = standard_enc / float(stats["mean_encryption_time_ns"])
        dec_speedup = standard_dec / float(stats["mean_decryption_time_ns"])
        enc_reduction = (1 - float(stats["mean_encryption_time_ns"]) / standard_enc) * 100
        dec_reduction = (1 - float(stats["mean_decryption_time_ns"]) / standard_dec) * 100
        rows.append(
            [
                MODE_LABELS[mode],
                ROUND_LABELS[mode],
                int(stats["payload_count"]),
                enc_ms,
                dec_ms,
                float(stats["mean_throughput_mb_s"]),
                f"{enc_speedup:.2f}x",
                f"{enc_reduction:.2f}%",
                f"{dec_speedup:.2f}x",
                f"{dec_reduction:.2f}%",
            ]
        )
    return rows


def print_overall_timing(timing_summary: dict) -> None:
    print_title("TABLE 3: OVERALL AES TIMING COMPARISON")
    print_table(
        [
            "Method",
            "Rounds",
            "Payloads",
            "Mean Enc Time (ms)",
            "Mean Dec Time (ms)",
            "Mean Throughput (MB/s)",
            "Enc Speedup",
            "Enc Time Reduction",
            "Dec Speedup",
            "Dec Time Reduction",
        ],
        speedup_rows(timing_summary["aggregate_modes"]),
    )


def bucket_rows(timings_dir: Path) -> list[dict[str, str]]:
    return load_csv(timings_dir / "bucket_timing_summary.csv")


def print_bucket_timing(timings_dir: Path) -> None:
    rows = bucket_rows(timings_dir)
    standard_by_bucket = {
        row["payload_bucket"]: row
        for row in rows
        if row["mode"] == "standard_aes_10"
    }
    table_rows = []

    for row in rows:
        bucket = row["payload_bucket"]
        mode = row["mode"]
        standard = standard_by_bucket[bucket]
        enc_ns = float(row["mean_encryption_time_ns"])
        dec_ns = float(row["mean_decryption_time_ns"])
        standard_enc_ns = float(standard["mean_encryption_time_ns"])
        standard_dec_ns = float(standard["mean_decryption_time_ns"])
        enc_reduction = (1 - enc_ns / standard_enc_ns) * 100
        dec_reduction = (1 - dec_ns / standard_dec_ns) * 100
        table_rows.append(
            [
                BUCKET_LABELS[bucket],
                MODE_LABELS[mode],
                int(float(row["payload_count"])),
                float(row["mean_payload_length"]),
                float(row["mean_rounds_used"]),
                ns_to_ms(enc_ns),
                ns_to_ms(dec_ns),
                float(row["mean_throughput_mb_s"]),
                f"{enc_reduction:.2f}%",
                f"{dec_reduction:.2f}%",
            ]
        )

    print_title("TABLE 4: TIMING COMPARISON BY PAYLOAD SIZE RANGE")
    print_table(
        [
            "Payload Range",
            "Method",
            "Payloads",
            "Avg Size (B)",
            "Avg Rounds",
            "Mean Enc (ms)",
            "Mean Dec (ms)",
            "Throughput (MB/s)",
            "Enc Reduction vs AES-10",
            "Dec Reduction vs AES-10",
        ],
        table_rows,
    )


def print_bucket_pivot(timings_dir: Path) -> None:
    rows = bucket_rows(timings_dir)
    by_bucket_mode = {
        (row["payload_bucket"], row["mode"]): row
        for row in rows
    }
    table_rows = []

    for bucket in ["1-128", "129-512", "513-1024", ">1024"]:
        standard = by_bucket_mode[(bucket, "standard_aes_10")]
        reduced = by_bucket_mode[(bucket, "fixed_reduced_aes_4")]
        adaptive = by_bucket_mode[(bucket, "adaptaes")]

        standard_enc = ns_to_ms(float(standard["mean_encryption_time_ns"]))
        standard_dec = ns_to_ms(float(standard["mean_decryption_time_ns"]))
        reduced_enc = ns_to_ms(float(reduced["mean_encryption_time_ns"]))
        reduced_dec = ns_to_ms(float(reduced["mean_decryption_time_ns"]))
        adaptive_enc = ns_to_ms(float(adaptive["mean_encryption_time_ns"]))
        adaptive_dec = ns_to_ms(float(adaptive["mean_decryption_time_ns"]))

        table_rows.append(
            [
                BUCKET_LABELS[bucket],
                int(float(standard["payload_count"])),
                float(standard["mean_payload_length"]),
                f"{standard_enc:.2f} / {standard_dec:.2f}",
                f"{reduced_enc:.2f} / {reduced_dec:.2f}",
                f"{adaptive_enc:.2f} / {adaptive_dec:.2f}",
                f'{float(adaptive["mean_rounds_used"]):.0f}',
                f"{(1 - adaptive_enc / standard_enc) * 100:.2f}%",
                f"{(1 - adaptive_dec / standard_dec) * 100:.2f}%",
            ]
        )

    print_title("TABLE 5: SIDE-BY-SIDE RESULT BY PAYLOAD RANGE")
    print_table(
        [
            "Payload Range",
            "Payloads",
            "Avg Size (B)",
            "Standard AES Enc/Dec (ms)",
            "Reduced AES Enc/Dec (ms)",
            "AdaptAES Enc/Dec (ms)",
            "AdaptAES Rounds",
            "AdaptAES Enc Reduction",
            "AdaptAES Dec Reduction",
        ],
        table_rows,
    )


def print_final_result_summary(timing_summary: dict) -> None:
    modes = timing_summary["aggregate_modes"]
    standard = modes["standard_aes_10"]
    table_rows = []

    for mode in ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]:
        stats = modes[mode]
        enc_ns = float(stats["mean_encryption_time_ns"])
        dec_ns = float(stats["mean_decryption_time_ns"])
        standard_enc_ns = float(standard["mean_encryption_time_ns"])
        standard_dec_ns = float(standard["mean_decryption_time_ns"])
        table_rows.append(
            [
                MODE_LABELS[mode],
                ROUND_LABELS[mode],
                int(stats["payload_count"]),
                ns_to_ms(enc_ns),
                ns_to_ms(dec_ns),
                float(stats["mean_throughput_mb_s"]),
                f"{standard_enc_ns / enc_ns:.2f}x",
                f"{(1 - enc_ns / standard_enc_ns) * 100:.2f}%",
                f"{standard_dec_ns / dec_ns:.2f}x",
                f"{(1 - dec_ns / standard_dec_ns) * 100:.2f}%",
            ]
        )

    print_title("TABLE 6: FINAL NUMERICAL RESULT SUMMARY")
    print_table(
        [
            "Method",
            "Rounds",
            "Payloads Tested",
            "Avg Enc Time (ms)",
            "Avg Dec Time (ms)",
            "Avg Throughput (MB/s)",
            "Enc Speedup",
            "Enc Time Reduction",
            "Dec Speedup",
            "Dec Time Reduction",
        ],
        table_rows,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--extracted-dir", type=Path, default=Path("results/extracted"))
    parser.add_argument("--timings-dir", type=Path, default=Path("results/timings"))
    args = parser.parse_args()

    timing_summary = load_json(args.timings_dir / "combined_timing_summary.json")
    print_dataset_overview(args.extracted_dir)
    print_payload_distribution(args.extracted_dir)
    print_overall_timing(timing_summary)
    print_bucket_timing(args.timings_dir)
    print_bucket_pivot(args.timings_dir)
    print_final_result_summary(timing_summary)


if __name__ == "__main__":
    main()
