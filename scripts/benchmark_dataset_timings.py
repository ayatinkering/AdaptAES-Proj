#!/usr/bin/env python3
"""Run AES timing benchmarks on PCAP-derived generated payloads.

This script uses the AES implementation files in scripts/:

- aes_core.py for standard AES-128 with 10 rounds
- aes_reduced.py for fixed reduced-round AES
- aes_adaptive.py for payload-size adaptive AES

It records only encryption/decryption timing and does not run avalanche tests.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path

from aes_adaptive import adaptaes_decrypt, adaptaes_encrypt
from aes_core import decrypt_data, encrypt_data
from aes_reduced import reduced_aes_decrypt, reduced_aes_encrypt


KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def load_manifest(manifest_path: Path, limit: int | None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with manifest_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(row)
            if limit is not None and len(rows) >= limit:
                break
    return rows


def read_payload(payload_bin_path: Path, row: dict[str, str]) -> bytes:
    payload_length = int(row["payload_length"])
    byte_offset = int(row["byte_offset"])
    with payload_bin_path.open("rb") as handle:
        handle.seek(byte_offset)
        payload = handle.read(payload_length)
    if len(payload) != payload_length:
        raise ValueError(
            f"payload_id={row['payload_id']} expected {payload_length} bytes, "
            f"got {len(payload)}"
        )
    return payload


def throughput_mb_s(payload_length: int, elapsed_ns: int) -> float:
    if elapsed_ns <= 0:
        return 0.0
    return (payload_length / (1024 * 1024)) / (elapsed_ns / 1_000_000_000)


def payload_bucket(payload_length: int) -> str:
    if payload_length <= 128:
        return "1-128"
    if payload_length <= 512:
        return "129-512"
    if payload_length <= 1024:
        return "513-1024"
    return ">1024"


def benchmark_payload(payload: bytes, payload_length: int) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []

    start = time.perf_counter_ns()
    standard_ciphertext = encrypt_data(payload, KEY)
    standard_enc_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    standard_plaintext = decrypt_data(standard_ciphertext, KEY)
    standard_dec_ns = time.perf_counter_ns() - start
    if standard_plaintext != payload:
        raise ValueError("standard AES decrypt mismatch")

    results.append(
        {
            "mode": "standard_aes_10",
            "rounds_used": 10,
            "encryption_time_ns": standard_enc_ns,
            "decryption_time_ns": standard_dec_ns,
            "throughput_mb_s": throughput_mb_s(payload_length, standard_enc_ns),
        }
    )

    start = time.perf_counter_ns()
    reduced_ciphertext = reduced_aes_encrypt(payload, KEY)
    reduced_enc_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    reduced_plaintext = reduced_aes_decrypt(reduced_ciphertext, KEY)
    reduced_dec_ns = time.perf_counter_ns() - start
    if reduced_plaintext != payload:
        raise ValueError("reduced AES decrypt mismatch")

    results.append(
        {
            "mode": "fixed_reduced_aes_4",
            "rounds_used": 4,
            "encryption_time_ns": reduced_enc_ns,
            "decryption_time_ns": reduced_dec_ns,
            "throughput_mb_s": throughput_mb_s(payload_length, reduced_enc_ns),
        }
    )

    start = time.perf_counter_ns()
    adaptive_ciphertext, adaptive_rounds = adaptaes_encrypt(payload, KEY)
    adaptive_enc_ns = time.perf_counter_ns() - start

    start = time.perf_counter_ns()
    adaptive_plaintext, decrypt_rounds = adaptaes_decrypt(
        adaptive_ciphertext,
        KEY,
        payload_length,
    )
    adaptive_dec_ns = time.perf_counter_ns() - start
    if adaptive_plaintext != payload:
        raise ValueError("AdaptAES decrypt mismatch")
    if adaptive_rounds != decrypt_rounds:
        raise ValueError("AdaptAES encrypt/decrypt round mismatch")

    results.append(
        {
            "mode": "adaptaes",
            "rounds_used": adaptive_rounds,
            "encryption_time_ns": adaptive_enc_ns,
            "decryption_time_ns": adaptive_dec_ns,
            "throughput_mb_s": throughput_mb_s(payload_length, adaptive_enc_ns),
        }
    )

    return results


def summarize(rows: list[dict[str, object]]) -> dict[str, object]:
    by_mode: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_mode[str(row["mode"])].append(row)

    mode_summaries: dict[str, object] = {}
    for mode, mode_rows in by_mode.items():
        enc = [int(row["encryption_time_ns"]) for row in mode_rows]
        dec = [int(row["decryption_time_ns"]) for row in mode_rows]
        throughput = [float(row["throughput_mb_s"]) for row in mode_rows]
        rounds = [int(row["rounds_used"]) for row in mode_rows]
        mode_summaries[mode] = {
            "payload_count": len(mode_rows),
            "mean_encryption_time_ns": statistics.fmean(enc),
            "median_encryption_time_ns": statistics.median(enc),
            "mean_decryption_time_ns": statistics.fmean(dec),
            "median_decryption_time_ns": statistics.median(dec),
            "mean_throughput_mb_s": statistics.fmean(throughput),
            "mean_rounds_used": statistics.fmean(rounds),
        }
    return mode_summaries


def benchmark_dataset(
    manifest_path: Path,
    payload_bin_path: Path,
    out_dir: Path,
    limit: int | None,
) -> dict[str, object]:
    dataset_name = manifest_path.name[: -len("_payload_manifest.csv")]
    rows = load_manifest(manifest_path, limit)
    output_rows: list[dict[str, object]] = []

    out_dir.mkdir(parents=True, exist_ok=True)
    output_csv = out_dir / f"{dataset_name}_timings.csv"
    summary_json = out_dir / f"{dataset_name}_timing_summary.json"

    with output_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "dataset_name",
                "payload_id",
                "payload_length",
                "payload_bucket",
                "mode",
                "rounds_used",
                "encryption_time_ns",
                "decryption_time_ns",
                "throughput_mb_s",
            ],
        )
        writer.writeheader()

        for row in rows:
            payload = read_payload(payload_bin_path, row)
            payload_length = int(row["payload_length"])
            for result in benchmark_payload(payload, payload_length):
                output_row = {
                    "dataset_name": dataset_name,
                    "payload_id": int(row["payload_id"]),
                    "payload_length": payload_length,
                    "payload_bucket": payload_bucket(payload_length),
                    **result,
                }
                writer.writerow(output_row)
                output_rows.append(output_row)

    summary = {
        "dataset_name": dataset_name,
        "payload_records": len(rows),
        "timing_rows": len(output_rows),
        "manifest": str(manifest_path),
        "payload_bin": str(payload_bin_path),
        "timings_csv": str(output_csv),
        "modes": summarize(output_rows),
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def combine_mode_summaries(dataset_summaries: list[dict[str, object]]) -> dict[str, object]:
    weighted: dict[str, dict[str, float]] = defaultdict(
        lambda: {
            "payload_count": 0,
            "mean_encryption_time_ns": 0.0,
            "mean_decryption_time_ns": 0.0,
            "mean_throughput_mb_s": 0.0,
            "mean_rounds_used": 0.0,
        }
    )

    for dataset_summary in dataset_summaries:
        modes = dataset_summary["modes"]
        for mode, stats in modes.items():
            count = int(stats["payload_count"])
            weighted[mode]["payload_count"] += count
            for metric in (
                "mean_encryption_time_ns",
                "mean_decryption_time_ns",
                "mean_throughput_mb_s",
                "mean_rounds_used",
            ):
                weighted[mode][metric] += float(stats[metric]) * count

    combined: dict[str, object] = {}
    for mode, stats in weighted.items():
        count = int(stats["payload_count"])
        combined[mode] = {
            "payload_count": count,
            "mean_encryption_time_ns": stats["mean_encryption_time_ns"] / count,
            "mean_decryption_time_ns": stats["mean_decryption_time_ns"] / count,
            "mean_throughput_mb_s": stats["mean_throughput_mb_s"] / count,
            "mean_rounds_used": stats["mean_rounds_used"] / count,
        }
    return combined


def summarize_by_bucket(timing_csv_paths: list[Path], out_csv_path: Path) -> list[dict[str, object]]:
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for csv_path in timing_csv_paths:
        with csv_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                groups[(row["payload_bucket"], row["mode"])].append(row)

    bucket_order = ["1-128", "129-512", "513-1024", ">1024"]
    mode_order = ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]
    rows: list[dict[str, object]] = []

    for bucket in bucket_order:
        for mode in mode_order:
            items = groups.get((bucket, mode), [])
            if not items:
                continue
            enc = [int(item["encryption_time_ns"]) for item in items]
            dec = [int(item["decryption_time_ns"]) for item in items]
            throughput = [float(item["throughput_mb_s"]) for item in items]
            rounds = [int(item["rounds_used"]) for item in items]
            payload_lengths = [int(item["payload_length"]) for item in items]
            rows.append(
                {
                    "payload_bucket": bucket,
                    "mode": mode,
                    "payload_count": len(items),
                    "mean_payload_length": statistics.fmean(payload_lengths),
                    "mean_rounds_used": statistics.fmean(rounds),
                    "mean_encryption_time_ns": statistics.fmean(enc),
                    "median_encryption_time_ns": statistics.median(enc),
                    "mean_decryption_time_ns": statistics.fmean(dec),
                    "median_decryption_time_ns": statistics.median(dec),
                    "mean_throughput_mb_s": statistics.fmean(throughput),
                }
            )

    with out_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "payload_bucket",
                "mode",
                "payload_count",
                "mean_payload_length",
                "mean_rounds_used",
                "mean_encryption_time_ns",
                "median_encryption_time_ns",
                "mean_decryption_time_ns",
                "median_decryption_time_ns",
                "mean_throughput_mb_s",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Payloads per dataset. Use a small value because pure Python AES is slow.",
    )
    args = parser.parse_args()

    summaries = []
    for manifest_path in sorted(args.payload_dir.glob("*_payload_manifest.csv")):
        dataset_name = manifest_path.name[: -len("_payload_manifest.csv")]
        payload_bin_path = args.payload_dir / f"{dataset_name}_payloads.bin"
        if not payload_bin_path.exists():
            raise FileNotFoundError(payload_bin_path)
        print(f"Timing {dataset_name} with limit={args.limit}")
        summaries.append(
            benchmark_dataset(
                manifest_path=manifest_path,
                payload_bin_path=payload_bin_path,
                out_dir=args.out_dir,
                limit=args.limit,
            )
        )

    timing_csv_paths = [Path(str(dataset_summary["timings_csv"])) for dataset_summary in summaries]
    bucket_summary_csv = args.out_dir / "bucket_timing_summary.csv"
    bucket_summary = summarize_by_bucket(timing_csv_paths, bucket_summary_csv)

    combined = {
        "payload_dir": str(args.payload_dir),
        "out_dir": str(args.out_dir),
        "payload_limit_per_dataset": args.limit,
        "aggregate_modes": combine_mode_summaries(summaries),
        "bucket_summary_csv": str(bucket_summary_csv),
        "bucket_summary": bucket_summary,
        "datasets": summaries,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "combined_timing_summary.json").write_text(
        json.dumps(combined, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(combined, indent=2))


if __name__ == "__main__":
    main()
