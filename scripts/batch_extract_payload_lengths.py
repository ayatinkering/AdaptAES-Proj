#!/usr/bin/env python3
"""Extract payload-length metadata for every PCAP in a folder."""

from __future__ import annotations

import argparse
from pathlib import Path

from extract_payload_lengths import extract


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    pcap_paths = sorted(args.pcap_dir.glob("*.pcap"))
    if not pcap_paths:
        raise SystemExit(f"No .pcap files found in {args.pcap_dir}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for pcap_path in pcap_paths:
        stem = pcap_path.stem.replace(".", "_")
        print(f"\n=== Extracting {pcap_path.name} ===")
        extract(
            pcap_path=pcap_path,
            csv_path=args.out_dir / f"{stem}_payload_lengths.csv",
            summary_path=args.out_dir / f"{stem}_summary.json",
        )


if __name__ == "__main__":
    main()
