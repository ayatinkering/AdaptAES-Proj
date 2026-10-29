"""Compare original AdaptAES, AdaptAES–ARX, adaptive-minimum-5, and AES-10.

Uses existing payload manifests; writes separate results, never legacy timings.
Times padded message encryption/decryption including key expansion. Rotating
order, one warm-up, then per-message medians. No security equivalence claim.
"""

import argparse
import csv
import json
import platform
import statistics
import time
from collections import defaultdict
from pathlib import Path

import aes_core
from aes_adaptive import adaptaes_encrypt, adaptaes_decrypt, select_rounds
from aes_adaptive_arx import adaptaes_arx_encrypt, adaptaes_arx_decrypt
from benchmark_dataset_timings import load_manifest, read_payload, payload_bucket


def fixed_encrypt(payload, key, rounds):
    padded = aes_core.pad_data(payload)
    return b"".join(aes_core.encrypt_block(padded[i:i+16], key, rounds) for i in range(0, len(padded), 16))


def fixed_decrypt(ciphertext, key, rounds):
    return aes_core.unpad_data(b"".join(aes_core.decrypt_block(ciphertext[i:i+16], key, rounds)
                                       for i in range(0, len(ciphertext), 16)))


def benchmark(payload, repeats):
    key = bytes(range(16))  # Public reproducible benchmark key, not a session secret.
    minimum_rounds = max(5, select_rounds(len(payload)))
    modes = {
        "aes10": (lambda: aes_core.encrypt_data(payload, key), lambda c: aes_core.decrypt_data(c, key)),
        "adaptaes": (lambda: adaptaes_encrypt(payload, key)[0], lambda c: adaptaes_decrypt(c, key, len(payload))[0]),
        "adaptaes_arx": (lambda: adaptaes_arx_encrypt(payload, key)[0], lambda c: adaptaes_arx_decrypt(c, key, len(payload))[0]),
        "adaptive_min5": (lambda: fixed_encrypt(payload, key, minimum_rounds), lambda c: fixed_decrypt(c, key, minimum_rounds)),
    }
    samples = {name: ([], []) for name in modes}
    names = list(modes)
    for repeat in range(repeats + 1):
        shift = repeat % len(names)
        for name in names[shift:] + names[:shift]:
            enc, dec = modes[name]
            start = time.perf_counter_ns()
            ciphertext = enc()
            enc_ns = time.perf_counter_ns() - start
            start = time.perf_counter_ns()
            recovered = dec(ciphertext)
            dec_ns = time.perf_counter_ns() - start
            if recovered != payload:
                raise ValueError(f"Round-trip failed: {name}")
            if repeat:
                samples[name][0].append(enc_ns)
                samples[name][1].append(dec_ns)
    return {name: (statistics.median(enc), statistics.median(dec)) for name, (enc, dec) in samples.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload-dir", type=Path, default=Path("results/payloads"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/adaptive_arx"))
    parser.add_argument("--limit", type=int, default=10, help="Manifest prefix per dataset; not stratified sampling")
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if min(args.limit, args.repeats) < 1:
        parser.error("limit and repeats must be positive")
    rows = []
    for manifest in sorted(args.payload_dir.glob("*_payload_manifest.csv")):
        name = manifest.name.removesuffix("_payload_manifest.csv")
        for record in load_manifest(manifest, args.limit):
            payload = read_payload(args.payload_dir / f"{name}_payloads.bin", record)
            for mode, (enc, dec) in benchmark(payload, args.repeats).items():
                rows.append(dict(dataset=name, payload_id=record["payload_id"], payload_bytes=len(payload),
                                 bucket=payload_bucket(len(payload)), mode=mode, encryption_ns=enc, decryption_ns=dec))
    if not rows:
        parser.error("No payload manifests found")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "timings.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    groups = defaultdict(list)
    for row in rows:
        groups[("overall", row["mode"])].append(row)
        groups[(row["bucket"], row["mode"])].append(row)
    summary = []
    for (bucket, mode), records in sorted(groups.items()):
        total_bytes = sum(r["payload_bytes"] for r in records)
        enc = sum(r["encryption_ns"] for r in records)
        dec = sum(r["decryption_ns"] for r in records)
        summary.append(dict(bucket=bucket, mode=mode, payloads=len(records), total_bytes=total_bytes,
                            mean_encryption_ms=enc / len(records) / 1e6, mean_decryption_ms=dec / len(records) / 1e6,
                            encryption_mib_s=total_bytes / 2**20 / (enc / 1e9),
                            decryption_mib_s=total_bytes / 2**20 / (dec / 1e9)))
    result = dict(python=platform.python_version(), platform=platform.platform(), repeats=args.repeats,
                  limit_per_dataset=args.limit, statistic="per-message median after warm-up; aggregate throughput = bytes / sum(medians)",
                  policy="ARX only in 1–128 byte branch; unchanged 6/8/10 branches", summary=summary)
    (args.out_dir / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Saved {len(rows)} measurements to {args.out_dir}")


if __name__ == "__main__":
    main()
