#!/usr/bin/env python3
"""Validate generated payload manifests against binary payload blobs."""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


def validate_manifest(manifest_path: Path, payload_bin_path: Path) -> tuple[int, int]:
    checked = 0
    total_bytes = 0

    with manifest_path.open("r", newline="", encoding="utf-8") as manifest, payload_bin_path.open(
        "rb"
    ) as payload_bin:
        reader = csv.DictReader(manifest)
        for row in reader:
            payload_length = int(row["payload_length"])
            byte_offset = int(row["byte_offset"])
            expected_hash = row["sha256"]

            payload_bin.seek(byte_offset)
            payload = payload_bin.read(payload_length)
            actual_hash = hashlib.sha256(payload).hexdigest()

            if len(payload) != payload_length:
                raise ValueError(
                    f"{manifest_path.name}: payload_id={row['payload_id']} expected "
                    f"{payload_length} bytes, got {len(payload)}"
                )
            if actual_hash != expected_hash:
                raise ValueError(
                    f"{manifest_path.name}: payload_id={row['payload_id']} hash mismatch"
                )

            checked += 1
            total_bytes += payload_length

    return checked, total_bytes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload-dir", required=True, type=Path)
    args = parser.parse_args()

    manifest_paths = sorted(args.payload_dir.glob("*_payload_manifest.csv"))
    if not manifest_paths:
        raise SystemExit(f"No *_payload_manifest.csv files found in {args.payload_dir}")

    total_checked = 0
    total_bytes = 0
    for manifest_path in manifest_paths:
        dataset_name = manifest_path.name[: -len("_payload_manifest.csv")]
        payload_bin_path = args.payload_dir / f"{dataset_name}_payloads.bin"
        if not payload_bin_path.exists():
            raise FileNotFoundError(payload_bin_path)

        checked, byte_count = validate_manifest(manifest_path, payload_bin_path)
        print(f"OK {dataset_name}: {checked} payloads, {byte_count} bytes")
        total_checked += checked
        total_bytes += byte_count

    print(f"Validated {total_checked} payloads, {total_bytes} bytes total")


if __name__ == "__main__":
    main()
