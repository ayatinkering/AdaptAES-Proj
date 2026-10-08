#!/usr/bin/env python3
"""Generate deterministic synthetic plaintext payloads from extracted lengths.

The anonymized HIKARI PCAPs preserve payload lengths, but not payload bytes. This
script creates reproducible plaintext bytes with the same lengths and stores
them in compact binary blobs with CSV metadata.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from pathlib import Path


def dataset_name_from_csv(path: Path) -> str:
    suffix = "_payload_lengths"
    stem = path.stem
    return stem[: -len(suffix)] if stem.endswith(suffix) else stem


def iter_payload_rows(csv_path: Path):
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            payload_length = int(row["payload_length"])
            if payload_length > 0:
                yield row


def sample_rows(csv_path: Path, sample_size: int | None, rng: random.Random):
    rows = list(iter_payload_rows(csv_path))
    if sample_size is None or sample_size >= len(rows):
        return rows
    return rng.sample(rows, sample_size)


def random_bytes(length: int, rng: random.Random) -> bytes:
    return rng.randbytes(length)


def generate_for_csv(
    csv_path: Path,
    out_dir: Path,
    sample_size: int | None,
    seed: int,
) -> dict[str, object]:
    dataset_name = dataset_name_from_csv(csv_path)
    rng = random.Random(f"{seed}:{dataset_name}")
    rows = sample_rows(csv_path, sample_size, rng)

    out_dir.mkdir(parents=True, exist_ok=True)
    payload_bin_path = out_dir / f"{dataset_name}_payloads.bin"
    metadata_csv_path = out_dir / f"{dataset_name}_payload_manifest.csv"
    summary_json_path = out_dir / f"{dataset_name}_payload_summary.json"

    total_bytes = 0
    min_length: int | None = None
    max_length = 0
    hash_all = hashlib.sha256()

    with payload_bin_path.open("wb") as payload_file, metadata_csv_path.open(
        "w", newline="", encoding="utf-8"
    ) as metadata_file:
        writer = csv.DictWriter(
            metadata_file,
            fieldnames=[
                "payload_id",
                "dataset_name",
                "source_packet_index",
                "timestamp_seconds",
                "protocol",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "payload_length",
                "adaptaes_rounds",
                "byte_offset",
                "sha256",
            ],
        )
        writer.writeheader()

        offset = 0
        for payload_id, row in enumerate(rows, start=1):
            payload_length = int(row["payload_length"])
            payload = random_bytes(payload_length, rng)
            payload_hash = hashlib.sha256(payload).hexdigest()

            payload_file.write(payload)
            hash_all.update(payload)

            writer.writerow(
                {
                    "payload_id": payload_id,
                    "dataset_name": dataset_name,
                    "source_packet_index": row["packet_index"],
                    "timestamp_seconds": row["timestamp_seconds"],
                    "protocol": row["protocol"],
                    "src_ip": row["src_ip"],
                    "dst_ip": row["dst_ip"],
                    "src_port": row["src_port"],
                    "dst_port": row["dst_port"],
                    "payload_length": payload_length,
                    "adaptaes_rounds": row["adaptaes_rounds"],
                    "byte_offset": offset,
                    "sha256": payload_hash,
                }
            )

            offset += payload_length
            total_bytes += payload_length
            min_length = payload_length if min_length is None else min(min_length, payload_length)
            max_length = max(max_length, payload_length)

    summary = {
        "dataset_name": dataset_name,
        "source_csv": str(csv_path),
        "payload_bin": str(payload_bin_path),
        "metadata_csv": str(metadata_csv_path),
        "sample_size_requested": sample_size,
        "payload_count": len(rows),
        "total_payload_bytes": total_bytes,
        "payload_min": min_length or 0,
        "payload_average": (total_bytes / len(rows)) if rows else 0,
        "payload_max": max_length,
        "seed": seed,
        "sha256_all_payload_bytes": hash_all.hexdigest(),
    }
    summary_json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--sample-size", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate payloads for every extracted row. This may create multi-GB outputs.",
    )
    args = parser.parse_args()

    csv_paths = sorted(args.input_dir.glob("*_payload_lengths.csv"))
    if not csv_paths:
        raise SystemExit(f"No *_payload_lengths.csv files found in {args.input_dir}")

    sample_size = None if args.all else args.sample_size
    summaries = [
        generate_for_csv(csv_path, args.out_dir, sample_size, args.seed)
        for csv_path in csv_paths
    ]

    combined = {
        "input_dir": str(args.input_dir),
        "out_dir": str(args.out_dir),
        "sample_size": sample_size,
        "seed": args.seed,
        "datasets": summaries,
        "total_payload_count": sum(int(s["payload_count"]) for s in summaries),
        "total_payload_bytes": sum(int(s["total_payload_bytes"]) for s in summaries),
    }
    combined_path = args.out_dir / "combined_payload_summary.json"
    combined_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print(json.dumps(combined, indent=2))


if __name__ == "__main__":
    main()
