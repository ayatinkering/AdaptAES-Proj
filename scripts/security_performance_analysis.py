#!/usr/bin/env python3
"""Round-wise security and bucketed performance analysis for AdaptAES.

Reads existing payload manifests/binaries and timing CSVs. It never creates or
substitutes payload inputs. See docs/security_performance_analysis.md for scope.
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
from aes_core import encrypt_block


KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ROUNDS = (4, 6, 8, 10)
BUCKETS = ((1, 128, "1-128"), (129, 512, "129-512"),
           (513, 1024, "513-1024"), (1025, math.inf, ">1024"))


def bucket(length: int) -> str:
    for lower, upper, label in BUCKETS:
        if lower <= length <= upper:
            return label
    raise ValueError(f"Unsupported payload length: {length}")


def hamming_bits(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("Ciphertext lengths differ")
    return sum(bin(a ^ b).count("1") for a, b in zip(left, right))


def metrics(payload: bytes, rounds: int) -> dict[str, float]:
    """Analyze the first AES block to isolate the block cipher's diffusion."""
    if len(payload) < 16:
        pad_len = 16 - len(payload)
        block = payload + bytes([pad_len]) * pad_len
    else:
        block = payload[:16]
    changed = bytearray(block)
    changed[0] ^= 1
    changed_key = bytearray(KEY)
    changed_key[0] ^= 1
    original_ct = encrypt_block(block, KEY, rounds=rounds)
    plain_ct = encrypt_block(bytes(changed), KEY, rounds=rounds)
    key_ct = encrypt_block(block, bytes(changed_key), rounds=rounds)
    bit_count = len(original_ct) * 8
    bit_diff = hamming_bits(original_ct, plain_ct)
    byte_diff = sum(a != b for a, b in zip(original_ct, plain_ct))
    values = list(original_ct)
    counts = Counter(values)
    entropy = -sum((n / len(values)) * math.log2(n / len(values))
                   for n in counts.values())
    expected = len(values) / 256
    chi = sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))
    mean_x = statistics.fmean(block)
    mean_y = statistics.fmean(original_ct)
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(block, original_ct))
    den_x = math.sqrt(sum((x - mean_x) ** 2 for x in block))
    den_y = math.sqrt(sum((y - mean_y) ** 2 for y in original_ct))
    corr = cov / (den_x * den_y) if den_x and den_y else 0.0
    return {
        "avalanche_percent": 100 * bit_diff / bit_count,
        "key_avalanche_percent": 100 * hamming_bits(original_ct, key_ct) / bit_count,
        "entropy_bits_per_byte": entropy,
        "chi_square": chi,
        "plaintext_ciphertext_correlation": corr,
        "npcr_byte_percent": 100 * byte_diff / len(original_ct),
        "uaci_byte_percent": 100 * sum(abs(a - b) for a, b in zip(original_ct, plain_ct)) / (255 * len(original_ct)),
    }


def read_manifest(manifest: Path, binary: Path) -> list[dict[str, object]]:
    if not manifest.exists() or not binary.exists():
        raise FileNotFoundError(f"Required existing payload inputs are missing: {manifest} or {binary}")
    rows = []
    with manifest.open(newline="", encoding="utf-8") as handle, binary.open("rb") as blob:
        for row in csv.DictReader(handle):
            size, offset = int(row["payload_length"]), int(row["byte_offset"])
            blob.seek(offset)
            payload = blob.read(size)
            if len(payload) != size:
                raise ValueError(f"Short payload read: {manifest.name} id={row['payload_id']}")
            rows.append({"dataset_name": row["dataset_name"], "payload_id": int(row["payload_id"]),
                         "payload_length": size, "payload": payload})
    return rows


def read_timings(path: Path) -> dict[tuple[str, int, str], dict[str, float]]:
    result = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            result[(row["dataset_name"], int(row["payload_id"]), row["mode"])] = {
                k: float(row[k]) for k in ("encryption_time_ns", "decryption_time_ns")
            }
    return result


def summarize(rows: list[dict[str, object]], timings: dict[tuple[str, int, str], dict[str, float]],
              max_payloads: int | None) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    selected = rows if max_payloads is None else rows[:max_payloads]
    security = []
    performance: dict[tuple[str, str], list[dict[str, float]]] = defaultdict(list)
    mode_rounds = {"standard_aes_10": 10, "fixed_reduced_aes_4": 4}
    for item in selected:
        size, pid, payload = int(item["payload_length"]), int(item["payload_id"]), item["payload"]
        group = bucket(size)
        chosen = 4 if size <= 128 else 6 if size <= 512 else 8 if size <= 1024 else 10
        round_for_mode = {**mode_rounds, "adaptaes": chosen}
        for mode, rounds in round_for_mode.items():
            sec = metrics(payload, rounds)
            security.append({"dataset_name": item["dataset_name"], "payload_id": pid,
                             "payload_length": size, "payload_bucket": group,
                             "mode": mode, "rounds": rounds, **sec})
            timing_key = (str(item["dataset_name"]), pid, mode)
            if timing_key in timings:
                performance[(group, mode)].append({
                    **timings[timing_key], "payload_length": size,
                })

    by_round: dict[int, list[dict[str, object]]] = defaultdict(list)
    for row in security:
        by_round[int(row["rounds"])].append(row)
    security_summary = []
    for rounds in ROUNDS:
        entries = by_round[rounds]
        entry = {"rounds": rounds, "sample_count": len(entries)}
        for metric in ("avalanche_percent", "key_avalanche_percent", "entropy_bits_per_byte",
                       "chi_square", "plaintext_ciphertext_correlation", "npcr_byte_percent",
                       "uaci_byte_percent"):
            entry[metric] = statistics.fmean(float(row[metric]) for row in entries) if entries else None
        security_summary.append(entry)

    perf_summary = []
    for _, _, group in BUCKETS:
        modes = ("standard_aes_10", "fixed_reduced_aes_4", "adaptaes")
        ref = None
        for mode in modes:
            items = [r for r in selected if bucket(int(r["payload_length"])) == group]
            tm = performance.get((group, mode), [])
            count = len(items)
            avg_size = statistics.fmean(int(r["payload_length"]) for r in items) if items else None
            enc = statistics.fmean(t["encryption_time_ns"] for t in tm) if tm else None
            dec = statistics.fmean(t["decryption_time_ns"] for t in tm) if tm else None
            matched_bytes = sum(t["payload_length"] for t in tm)
            enc_tp = (matched_bytes / (1024 * 1024)) / (sum(t["encryption_time_ns"] for t in tm) / 1e9) if tm else None
            dec_tp = (matched_bytes / (1024 * 1024)) / (sum(t["decryption_time_ns"] for t in tm) / 1e9) if tm else None
            entry = {"payload_bucket": group, "mode": mode, "payload_count": count,
                     "rounds_used": (10 if mode == "standard_aes_10" else
                                     4 if mode == "fixed_reduced_aes_4" else
                                     4 if group == "1-128" else 6 if group == "129-512" else
                                     8 if group == "513-1024" else 10),
                     "average_payload_bytes": avg_size, "mean_encryption_time_ns": enc,
                     "mean_decryption_time_ns": dec, "encryption_throughput_mib_s": enc_tp,
                     "decryption_throughput_mib_s": dec_tp, "timing_sample_count": len(tm)}
            if mode == "standard_aes_10":
                ref = entry
                entry.update({"speedup_vs_aes10": 1.0, "time_reduction_percent_vs_aes10": 0.0,
                              "decryption_speedup_vs_aes10": 1.0,
                              "decryption_time_reduction_percent_vs_aes10": 0.0})
            elif ref and enc and ref["mean_encryption_time_ns"]:
                entry.update({"speedup_vs_aes10": ref["mean_encryption_time_ns"] / enc,
                              "time_reduction_percent_vs_aes10": 100 * (1 - enc / ref["mean_encryption_time_ns"])})
                ref_dec = ref["mean_decryption_time_ns"]
                if dec and ref_dec:
                    entry.update({"decryption_speedup_vs_aes10": ref_dec / dec,
                                  "decryption_time_reduction_percent_vs_aes10": 100 * (1 - dec / ref_dec)})
            sec_rows = [r for r in security if r["payload_bucket"] == group and r["mode"] == mode]
            for metric in ("avalanche_percent", "key_avalanche_percent", "entropy_bits_per_byte",
                           "chi_square", "plaintext_ciphertext_correlation",
                           "npcr_byte_percent", "uaci_byte_percent"):
                entry[metric] = statistics.fmean(float(r[metric]) for r in sec_rows) if sec_rows else None
            perf_summary.append(entry)
    return security_summary, perf_summary, security


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if rows:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", type=Path, default=Path("results/payloads"))
    parser.add_argument("--timing-dir", type=Path, default=Path("results/timings"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/analysis"))
    parser.add_argument("--max-payloads-per-dataset", type=int, default=None,
                        help="Optional deterministic prefix cap; default analyzes all available payloads.")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    all_rows, all_timing = [], {}
    for manifest in sorted(args.payload_dir.glob("*_payload_manifest.csv")):
        name = manifest.name[:-len("_payload_manifest.csv")]
        binary = args.payload_dir / f"{name}_payloads.bin"
        all_rows.extend(read_manifest(manifest, binary))
        timing_file = args.timing_dir / f"{name}_timings.csv"
        if timing_file.exists():
            all_timing.update(read_timings(timing_file))
    if not all_rows:
        raise SystemExit(f"No existing payload manifests found in {args.payload_dir}")
    security_summary, performance, per_payload = summarize(all_rows, all_timing, args.max_payloads_per_dataset)
    write_csv(args.out_dir / "roundwise_security_summary.csv", security_summary)
    write_csv(args.out_dir / "bucket_security_performance_summary.csv", performance)
    write_csv(args.out_dir / "security_per_payload.csv", per_payload)
    frequency_rows = []
    by_round: dict[int, Counter[int]] = defaultdict(Counter)
    round_samples: Counter[int] = Counter()
    payload_lookup = {(str(item["dataset_name"]), int(item["payload_id"])): item["payload"]
                      for item in all_rows}
    for row in per_payload:
        rounds = int(row["rounds"])
        payload_id = int(row["payload_id"])
        dataset_name = str(row["dataset_name"])
        # Re-read the original block bytes for frequency counts from the same
        # stored payload record; no payload data is regenerated.
        payload = payload_lookup[(dataset_name, payload_id)]
        if len(payload) < 16:
            pad_len = 16 - len(payload)
            block = payload + bytes([pad_len]) * pad_len
        else:
            block = payload[:16]
        encrypted = encrypt_block(block, KEY, rounds=rounds)
        by_round[rounds].update(encrypted)
        round_samples[rounds] += 1
    for rounds in ROUNDS:
        counts = by_round[rounds]
        for value in range(256):
            frequency_rows.append({"rounds": rounds, "byte_value": value,
                                   "count": counts.get(value, 0),
                                   "sample_count": round_samples[rounds]})
    write_csv(args.out_dir / "byte_frequency_by_round.csv", frequency_rows)
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(2, 2, figsize=(14, 8), sharex=True)
        for ax, rounds in zip(axes.flat, ROUNDS):
            values = [by_round[rounds].get(v, 0) for v in range(256)]
            ax.bar(range(256), values, width=1.0)
            ax.set_title(f"{rounds} rounds (n={round_samples[rounds]} blocks)")
            ax.set_ylabel("Byte frequency")
            ax.set_xlim(0, 255)
        for ax in axes[-1]:
            ax.set_xlabel("Ciphertext byte value")
        fig.suptitle("Ciphertext byte frequencies by AES round count")
        fig.tight_layout()
        fig.savefig(args.out_dir / "byte_frequency_by_round.png", dpi=160)
        plt.close(fig)
    except ImportError:
        print("matplotlib unavailable; wrote byte_frequency_by_round.csv without the plot")
    metadata = {
        "payload_records_available": len(all_rows),
        "timing_rows_available": len(all_timing),
        "security_measurement": "First AES block per sample; one-bit input/key flips.",
        "npcr_uaci_note": "Byte-level adaptations computed over the first 16-byte ciphertext block; not image NPCR/UACI.",
        "correlation_note": "Pearson correlation of corresponding bytes in the first plaintext and ciphertext blocks.",
        "payload_note": "Uses stored payload binaries only; no payload bytes are generated by this script.",
        "missing_payload_datasets": [p.name for p in sorted(args.payload_dir.glob("*_payload_summary.json"))
                                     if not (args.payload_dir / (p.name[:-len("_payload_summary.json")] + "_payload_manifest.csv")).exists()],
        "roundwise_security_summary": security_summary,
        "bucket_performance_security_summary": performance,
        "round_policy": {"1-128": 4, "129-512": 6, "513-1024": 8, ">1024": 10},
        "missing_timing_payload_matches": max(0, len(all_rows) * 3 - sum(
            1 for item in all_rows for mode in ("standard_aes_10", "fixed_reduced_aes_4", "adaptaes")
            if (str(item["dataset_name"]), int(item["payload_id"]), mode) in all_timing)),
        "analysis_limit_per_dataset": args.max_payloads_per_dataset,
    }
    (args.out_dir / "security_performance_summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps({k: metadata[k] for k in ("payload_records_available", "timing_rows_available", "missing_payload_datasets")}, indent=2))


if __name__ == "__main__":
    main()
