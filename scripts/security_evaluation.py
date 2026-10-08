#!/usr/bin/env python3
"""Security metrics for Standard AES, Reduced AES, and AdaptAES.

Measured metrics:
- Plaintext avalanche effect
- Key avalanche effect
- Shannon entropy
- Byte frequency min/max/stddev
- Chi-square byte uniformity
- Plaintext-ciphertext correlation coefficient
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from aes_adaptive import adaptaes_encrypt
from aes_core import encrypt_data
from aes_reduced import reduced_aes_encrypt


KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
MODE_LABELS = ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"]


def payload_bucket(payload_length: int) -> str:
    if payload_length <= 128:
        return "1-128"
    if payload_length <= 512:
        return "129-512"
    if payload_length <= 1024:
        return "513-1024"
    return ">1024"


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


def encrypt_mode(payload: bytes, key: bytes, mode: str) -> tuple[bytes, int]:
    if mode == "standard_aes_10":
        return encrypt_data(payload, key), 10
    if mode == "fixed_reduced_aes_4":
        return reduced_aes_encrypt(payload, key), 4
    if mode == "adaptaes":
        ciphertext, rounds = adaptaes_encrypt(payload, key)
        return ciphertext, rounds
    raise ValueError(f"unknown mode: {mode}")


def flip_first_bit(data: bytes) -> bytes:
    if not data:
        raise ValueError("cannot flip bit in empty bytes")
    changed = bytearray(data)
    changed[0] ^= 0x01
    return bytes(changed)


def different_bits(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def avalanche_ratio(left: bytes, right: bytes) -> float:
    compared_len = min(len(left), len(right))
    if compared_len == 0:
        return 0.0
    return different_bits(left[:compared_len], right[:compared_len]) / (compared_len * 8)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def byte_frequency_stats(data: bytes) -> tuple[int, int, float]:
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return min(counts), max(counts), statistics.pstdev(counts)


def chi_square_uniform(data: bytes) -> float:
    if not data:
        return 0.0
    expected = len(data) / 256
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return sum(((observed - expected) ** 2) / expected for observed in counts)


def pearson_correlation(left: bytes, right: bytes) -> float:
    compared_len = min(len(left), len(right))
    if compared_len < 2:
        return 0.0
    x = list(left[:compared_len])
    y = list(right[:compared_len])
    mean_x = statistics.fmean(x)
    mean_y = statistics.fmean(y)
    numerator = sum((a - mean_x) * (b - mean_y) for a, b in zip(x, y))
    denom_x = math.sqrt(sum((a - mean_x) ** 2 for a in x))
    denom_y = math.sqrt(sum((b - mean_y) ** 2 for b in y))
    if denom_x == 0 or denom_y == 0:
        return 0.0
    return numerator / (denom_x * denom_y)


def evaluate_payload(payload: bytes, mode: str) -> dict[str, float | int]:
    ciphertext, rounds = encrypt_mode(payload, KEY, mode)
    plaintext_flipped = flip_first_bit(payload)
    ciphertext_plaintext_flip, _ = encrypt_mode(plaintext_flipped, KEY, mode)
    key_flipped = flip_first_bit(KEY)
    ciphertext_key_flip, _ = encrypt_mode(payload, key_flipped, mode)

    # AES is a block cipher. With the simple block-by-block mode used in this
    # project, flipping one plaintext bit affects the corresponding 16-byte
    # ciphertext block. Measure avalanche on that block to avoid diluting the
    # score across unrelated payload blocks.
    plaintext_avalanche = avalanche_ratio(ciphertext[:16], ciphertext_plaintext_flip[:16])
    key_avalanche = avalanche_ratio(ciphertext[:16], ciphertext_key_flip[:16])
    freq_min, freq_max, freq_stddev = byte_frequency_stats(ciphertext)

    return {
        "rounds_used": rounds,
        "ciphertext_length": len(ciphertext),
        "plaintext_avalanche_ratio": plaintext_avalanche,
        "plaintext_avalanche_percent": plaintext_avalanche * 100,
        "key_avalanche_ratio": key_avalanche,
        "key_avalanche_percent": key_avalanche * 100,
        "ciphertext_entropy": shannon_entropy(ciphertext),
        "byte_frequency_min": freq_min,
        "byte_frequency_max": freq_max,
        "byte_frequency_stddev": freq_stddev,
        "chi_square": chi_square_uniform(ciphertext),
        "correlation_coefficient": pearson_correlation(payload, ciphertext),
    }


def summarize(rows: list[dict[str, object]], group_fields: list[str]) -> list[dict[str, object]]:
    groups: dict[tuple[object, ...], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in group_fields)].append(row)

    summaries: list[dict[str, object]] = []
    for key, items in sorted(groups.items()):
        summary = {field: key[index] for index, field in enumerate(group_fields)}
        summary.update(
            {
                "sample_count": len(items),
                "mean_payload_length": statistics.fmean(
                    int(item["payload_length"]) for item in items
                ),
                "mean_rounds_used": statistics.fmean(int(item["rounds_used"]) for item in items),
                "mean_plaintext_avalanche_percent": statistics.fmean(
                    float(item["plaintext_avalanche_percent"]) for item in items
                ),
                "mean_key_avalanche_percent": statistics.fmean(
                    float(item["key_avalanche_percent"]) for item in items
                ),
                "mean_ciphertext_entropy": statistics.fmean(
                    float(item["ciphertext_entropy"]) for item in items
                ),
                "mean_byte_frequency_stddev": statistics.fmean(
                    float(item["byte_frequency_stddev"]) for item in items
                ),
                "mean_chi_square": statistics.fmean(float(item["chi_square"]) for item in items),
                "mean_correlation_coefficient": statistics.fmean(
                    float(item["correlation_coefficient"]) for item in items
                ),
            }
        )
        summaries.append(summary)
    return summaries


def write_summary_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def evaluate_dataset(
    manifest_path: Path,
    payload_bin_path: Path,
    out_dir: Path,
    limit: int | None,
) -> dict[str, object]:
    dataset_name = manifest_path.name[: -len("_payload_manifest.csv")]
    manifest_rows = load_manifest(manifest_path, limit)
    result_rows: list[dict[str, object]] = []

    out_dir.mkdir(parents=True, exist_ok=True)
    metrics_csv = out_dir / f"{dataset_name}_security_metrics.csv"
    summary_json = out_dir / f"{dataset_name}_security_summary.json"

    with metrics_csv.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "dataset_name",
            "payload_id",
            "payload_length",
            "payload_bucket",
            "mode",
            "rounds_used",
            "ciphertext_length",
            "plaintext_avalanche_ratio",
            "plaintext_avalanche_percent",
            "key_avalanche_ratio",
            "key_avalanche_percent",
            "ciphertext_entropy",
            "byte_frequency_min",
            "byte_frequency_max",
            "byte_frequency_stddev",
            "chi_square",
            "correlation_coefficient",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for manifest_row in manifest_rows:
            payload = read_payload(payload_bin_path, manifest_row)
            payload_length = int(manifest_row["payload_length"])
            for mode in MODE_LABELS:
                metrics = evaluate_payload(payload, mode)
                result_row = {
                    "dataset_name": dataset_name,
                    "payload_id": int(manifest_row["payload_id"]),
                    "payload_length": payload_length,
                    "payload_bucket": payload_bucket(payload_length),
                    "mode": mode,
                    **metrics,
                }
                writer.writerow(result_row)
                result_rows.append(result_row)

    mode_summary = summarize(result_rows, ["mode"])
    bucket_summary = summarize(result_rows, ["payload_bucket", "mode"])
    summary = {
        "dataset_name": dataset_name,
        "payload_records": len(manifest_rows),
        "security_rows": len(result_rows),
        "metrics_csv": str(metrics_csv),
        "mode_summary": mode_summary,
        "bucket_summary": bucket_summary,
    }
    summary_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    all_metric_rows: list[dict[str, object]] = []
    dataset_summaries = []

    for manifest_path in sorted(args.payload_dir.glob("*_payload_manifest.csv")):
        dataset_name = manifest_path.name[: -len("_payload_manifest.csv")]
        payload_bin_path = args.payload_dir / f"{dataset_name}_payloads.bin"
        if not payload_bin_path.exists():
            raise FileNotFoundError(payload_bin_path)
        print(f"Evaluating security metrics for {dataset_name} with limit={args.limit}")
        summary = evaluate_dataset(manifest_path, payload_bin_path, args.out_dir, args.limit)
        dataset_summaries.append(summary)
        with Path(summary["metrics_csv"]).open("r", newline="", encoding="utf-8") as handle:
            all_metric_rows.extend(csv.DictReader(handle))

    combined_mode_summary = summarize(all_metric_rows, ["mode"])
    combined_bucket_summary = summarize(all_metric_rows, ["payload_bucket", "mode"])
    mode_summary_csv = args.out_dir / "security_mode_summary.csv"
    bucket_summary_csv = args.out_dir / "security_bucket_summary.csv"
    write_summary_csv(mode_summary_csv, combined_mode_summary)
    write_summary_csv(bucket_summary_csv, combined_bucket_summary)

    combined = {
        "payload_dir": str(args.payload_dir),
        "out_dir": str(args.out_dir),
        "payload_limit_per_dataset": args.limit,
        "total_metric_rows": len(all_metric_rows),
        "mode_summary_csv": str(mode_summary_csv),
        "bucket_summary_csv": str(bucket_summary_csv),
        "mode_summary": combined_mode_summary,
        "bucket_summary": combined_bucket_summary,
        "datasets": dataset_summaries,
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "combined_security_summary.json").write_text(
        json.dumps(combined, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(combined, indent=2))


if __name__ == "__main__":
    main()
