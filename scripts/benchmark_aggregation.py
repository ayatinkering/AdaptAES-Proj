"""Replay capture-derived sizes and arrival times through authenticated aggregation."""

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import statistics
import time
from collections import Counter
from decimal import Decimal
from itertools import islice
from pathlib import Path

import cryptography
from aggregate_records import MODES, Packet, aggregate
from authenticated_records import RecordCipher


def load_trace(path, limit, seed=42):
    rng, flows, packets = random.Random(f"{seed}:{path.stem}"), {}, []
    with path.open(newline="") as handle:
        for row in islice(csv.DictReader(handle), limit):
            identity = tuple(row[k] for k in ("protocol", "src_ip", "src_port", "dst_ip", "dst_port"))
            flow = flows.setdefault(identity, len(flows))
            length = int(row["payload_length"])
            if length <= 0:
                raise ValueError("Trace payload lengths must be positive.")
            packets.append(Packet(int(Decimal(row["timestamp_seconds"]) * 10**9), flow,
                                  rng.randbytes(length), int(row["packet_index"])))
    if not packets:
        raise ValueError(f"Empty trace: {path}")
    packets.sort(key=lambda packet: packet.timestamp_ns)
    origin = packets[0].timestamp_ns
    return [Packet(p.timestamp_ns - origin, p.flow, p.payload, p.packet_id) for p in packets]


def controlled_trace(bursty, count=1024):
    # Synthetic illustrations are reported separately from capture-derived workloads.
    return [Packet(i * (10_000 if bursty else 5_000_000), 0, bytes([i % 256]) * 64, i)
            for i in range(count)]


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def trial(packets, mode, policy):
    cipher = RecordCipher()  # Fresh key; key generation is outside measured stages.
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    batches = aggregate(packets, mode, **policy)
    result = {"schedule_wall_ns": time.perf_counter_ns() - wall,
              "schedule_cpu_ns": time.process_time_ns() - cpu}
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    records = [cipher.seal(b.flow, [p.payload for p in b.packets]) for b in batches]
    result.update(encryption_wall_ns=time.perf_counter_ns() - wall,
                  encryption_cpu_ns=time.process_time_ns() - cpu)
    wall, cpu = time.perf_counter_ns(), time.process_time_ns()
    decoded = [cipher.open(record, batch.flow) for record, batch in zip(records, batches)]
    result.update(decryption_wall_ns=time.perf_counter_ns() - wall,
                  decryption_cpu_ns=time.process_time_ns() - cpu)
    if decoded != [[p.payload for p in b.packets] for b in batches]:
        raise ValueError("Authenticated round-trip mismatch.")
    if sorted(p.packet_id for b in batches for p in b.packets) != sorted(p.packet_id for p in packets):
        raise ValueError("Aggregation lost or duplicated a message.")
    result["processing_wall_ns"] = sum(result[k] for k in ("schedule_wall_ns", "encryption_wall_ns", "decryption_wall_ns"))
    result["processing_cpu_ns"] = sum(result[k] for k in ("schedule_cpu_ns", "encryption_cpu_ns", "decryption_cpu_ns"))
    return result, batches, sum(map(len, records))


def benchmark(packets, policy, repeats):
    timings = {mode: [] for mode in MODES}
    details = {}
    for repeat in range(repeats + 1):
        # One warm-up per policy, followed by rotating execution order.
        for mode in MODES[repeat % 3:] + MODES[:repeat % 3]:
            timing, batches, wire_bytes = trial(packets, mode, policy)
            if repeat:
                timings[mode].append(timing)
            details[mode] = batches, wire_bytes
    payload_bytes = sum(len(p.payload) for p in packets)
    rows = []
    for mode in MODES:
        batches, wire_bytes = details[mode]
        delays = [b.released_ns - p.timestamp_ns for b in batches for p in b.packets]
        if max(delays) > policy["max_delay_ns"]:
            raise ValueError("Queueing budget exceeded.")
        row = {"mode": mode, "message_count": len(packets), "flow_count": len({p.flow for p in packets}),
               "payload_bytes": payload_bytes, "record_count": len(batches), "wire_bytes": wire_bytes,
               "overhead_bytes": wire_bytes - payload_bytes,
               "max_messages_per_record": max(len(b.packets) for b in batches),
               "mean_messages_per_record": len(packets) / len(batches),
               "queue_p50_us": percentile(delays, .50) / 1000,
               "queue_p95_us": percentile(delays, .95) / 1000,
               "queue_p99_us": percentile(delays, .99) / 1000,
               "queue_max_us": max(delays) / 1000}
        for key in timings[mode][0]:
            row[key] = statistics.median(t[key] for t in timings[mode])
        row["processing_cpu_us_per_message"] = row["processing_cpu_ns"] / len(packets) / 1000
        row["processing_wall_mib_s"] = payload_bytes / 2**20 / (row["processing_wall_ns"] / 1e9)
        row["flush_reasons"] = json.dumps(dict(sorted(Counter(b.reason for b in batches).items())))
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=Path("results/extracted"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/aggregation"))
    parser.add_argument("--limit", type=int, default=5000, help="First N payload rows per capture, sorted by time.")
    parser.add_argument("--repeats", type=int, default=11)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-delay-us", type=int, default=1000)
    parser.add_argument("--max-packets", type=int, default=8)
    parser.add_argument("--max-bytes", type=int, default=16384)
    parser.add_argument("--small-bytes", type=int, default=512)
    args = parser.parse_args()
    if min(args.limit, args.repeats, args.max_delay_us, args.max_packets, args.max_bytes, args.small_bytes) < 1:
        parser.error("All sample sizes and policy bounds must be positive.")
    paths = sorted(args.input_dir.glob("*_payload_lengths.csv"))
    if not paths:
        parser.error(f"No extracted payload-length CSVs in {args.input_dir}")
    policy = {"max_delay_ns": args.max_delay_us * 1000, "max_packets": args.max_packets,
              "max_bytes": args.max_bytes, "small_bytes": args.small_bytes}
    rows, sources = [], []
    for path in paths:
        packets = load_trace(path, args.limit, args.seed)
        with path.open("rb") as handle:
            source_hash = hashlib.file_digest(handle, "sha256").hexdigest()
        name = path.stem.removesuffix("_payload_lengths")
        sources.append({"dataset": name, "source_sha256": source_hash,
                        "payload_sha256": hashlib.sha256(b"".join(p.payload for p in packets)).hexdigest()})
        rows.extend({"dataset": name, "workload": "capture", **row} for row in benchmark(packets, policy, args.repeats))
        print(f"Benchmarked {name}: {len(packets)} messages", flush=True)
    for bursty in (True, False):
        rows.extend({"dataset": "controlled_burst" if bursty else "controlled_sparse", "workload": "synthetic",
                     **row} for row in benchmark(controlled_trace(bursty), policy, args.repeats))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    metadata = {"python": platform.python_version(), "platform": platform.platform(),
                "cryptography": cryptography.__version__, "seed": args.seed, "limit_per_capture": args.limit,
                "repeats": args.repeats, "policy": policy, "sources": sources,
                "timing": "Per-workload median after one warm-up; mode order rotates. Framing and scheduling included; key generation and correctness checks excluded.",
                "queueing": "Simulated trace-time waiting only. Does not model CPU backlog, transport, or end-to-end latency.",
                "wire": "Record header, encrypted length prefixes, payloads and full 16-byte authentication tags; excludes transport headers.",
                "session": "Fresh random AES-128 key per trial; monotonic 96-bit record nonces; full-round AES-GCM in every mode.",
                "synthetic": "1024 64-byte messages in one flow, spaced 10 us for burst or 5 ms for sparse."}
    (args.out_dir / "methodology.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Saved {len(rows)} summaries to {args.out_dir}")


if __name__ == "__main__":
    main()
